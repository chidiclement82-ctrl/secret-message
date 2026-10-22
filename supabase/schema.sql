-- Secret Message inbox database (Supabase / Postgres).
--
-- The database only ever holds ciphertext: messages are encrypted in the
-- sender's browser to the owner's public key, and the owner's private key is
-- stored wrapped with a key derived from their passphrase (see lib.js).
--
-- The tables are not reachable through the API at all. Visitors and the
-- owner only call the functions below, which check what they need to.

create table public.inbox (
  id int primary key default 1 check (id = 1),
  public_key text,          -- owner's ECDH P-256 public key (base64url, raw)
  salt text,                -- PBKDF2 salt for the passphrase (base64url)
  auth_hash text,           -- sha256 of the passphrase-derived access token (hex)
  wrapped_key text,         -- owner's private key, AES-GCM encrypted (base64url)
  setup_code_hash text,     -- sha256 of the one-time setup code (hex)
  created_at timestamptz not null default now()
);
alter table public.inbox enable row level security;
revoke all on public.inbox from anon, authenticated;

create table public.messages (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  blob text not null check (length(blob) between 100 and 16000)
);
create index messages_created_at on public.messages (created_at desc);
alter table public.messages enable row level security;
revoke all on public.messages from anon, authenticated;

-- Token check shared by the owner-only functions.
create function public._owner_ok(token text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.inbox
    where auth_hash is not null
      and token ~ '^[0-9a-f]{64}$'
      and auth_hash = encode(sha256(decode(token, 'hex')), 'hex')
  );
$$;
revoke all on function public._owner_ok(text) from public, anon, authenticated;

-- Public: what a sender needs to encrypt a message.
create function public.get_inbox() returns json
language sql stable security definer set search_path = '' as $$
  select json_build_object('public_key', public_key, 'salt', salt)
  from public.inbox where id = 1;
$$;

-- One-time setup, guarded by a setup code given to the owner.
create function public.setup_inbox(setup_code text, public_key text, salt text, auth_hash text, wrapped_key text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  update public.inbox i
     set public_key = setup_inbox.public_key,
         salt = setup_inbox.salt,
         auth_hash = setup_inbox.auth_hash,
         wrapped_key = setup_inbox.wrapped_key,
         setup_code_hash = null
   where i.id = 1
     and i.public_key is null
     and i.setup_code_hash = encode(sha256(convert_to(setup_code, 'UTF8')), 'hex');
  if not found then
    raise exception 'invalid setup code' using errcode = '28000';
  end if;
end;
$$;

-- Public: drop off an encrypted message. A global rate limit keeps a flood
-- of junk from filling the inbox.
create function public.send_message(blob text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.inbox where public_key is not null) then
    raise exception 'inbox not set up' using errcode = 'P0001';
  end if;
  if blob !~ '^[A-Za-z0-9_-]+$' then
    raise exception 'bad message' using errcode = '22023';
  end if;
  if (select count(*) from public.messages where created_at > now() - interval '1 minute') >= 20 then
    raise exception 'too many messages, try again in a minute' using errcode = 'P0001';
  end if;
  insert into public.messages (blob) values (send_message.blob);
end;
$$;

-- Owner: everything needed to read the inbox.
create function public.open_inbox(token text) returns json
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public._owner_ok(token) then
    raise exception 'wrong passphrase' using errcode = '28000';
  end if;
  return json_build_object(
    'wrapped_key', (select wrapped_key from public.inbox where id = 1),
    'messages', coalesce((
      select json_agg(json_build_object('id', id, 'created_at', created_at, 'blob', blob) order by created_at desc)
      from public.messages), '[]'::json));
end;
$$;

-- Owner: remove one message.
create function public.delete_message(token text, message_id bigint) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public._owner_ok(token) then
    raise exception 'wrong passphrase' using errcode = '28000';
  end if;
  delete from public.messages where id = message_id;
end;
$$;

-- Owner: change passphrase (re-wraps the same private key).
create function public.change_passphrase(token text, salt text, auth_hash text, wrapped_key text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public._owner_ok(token) then
    raise exception 'wrong passphrase' using errcode = '28000';
  end if;
  update public.inbox i
     set salt = change_passphrase.salt,
         auth_hash = change_passphrase.auth_hash,
         wrapped_key = change_passphrase.wrapped_key
   where i.id = 1;
end;
$$;

revoke all on function public.get_inbox(), public.setup_inbox(text, text, text, text, text),
  public.send_message(text), public.open_inbox(text), public.delete_message(text, bigint),
  public.change_passphrase(text, text, text, text) from public;
grant execute on function public.get_inbox(), public.setup_inbox(text, text, text, text, text),
  public.send_message(text), public.open_inbox(text), public.delete_message(text, bigint),
  public.change_passphrase(text, text, text, text) to anon, authenticated;

-- Then, to let the owner claim the inbox, store the hash of a one-time code:
--   insert into public.inbox (id, setup_code_hash)
--   values (1, encode(sha256(convert_to('<CODE>', 'UTF8')), 'hex'));
