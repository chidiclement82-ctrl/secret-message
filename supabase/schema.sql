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

-- First version (one-way messages), retired: no longer callable by visitors.
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

-- Owner: remove one message (first version, one-way messages).
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

-- ---------------------------------------------------------------------------
-- Conversations. Each starts on a visitor's device with a random secret; the
-- database only sees sha256(thread token) as the thread id, the conversation
-- key sealed to the owner (envelope), and AES-GCM ciphertext (see lib.js).

create table public.threads (
  id text primary key check (id ~ '^[0-9a-f]{64}$'),   -- sha256 of the sender's thread token
  envelope text not null check (length(envelope) between 100 and 1000), -- thread key, sealed to the owner
  created_at timestamptz not null default now(),
  last_at timestamptz not null default now(),
  last_from_owner boolean not null default false
);
alter table public.threads enable row level security;
revoke all on public.threads from anon, authenticated;

create table public.thread_messages (
  id bigint generated always as identity primary key,
  thread_id text not null references public.threads (id) on delete cascade,
  from_owner boolean not null,
  created_at timestamptz not null default now(),
  blob text not null check (length(blob) between 40 and 16000)
);
create index thread_messages_thread on public.thread_messages (thread_id, created_at);
alter table public.thread_messages enable row level security;
revoke all on public.thread_messages from anon, authenticated;

-- Public: a visitor sends a message in their conversation, creating it on
-- the first message. Only someone holding the thread token can add to it.
create function public.send_to_thread(thread_token text, envelope text, blob text)
returns void language plpgsql security definer set search_path = '' as $$
declare tid text;
begin
  if not exists (select 1 from public.inbox where public_key is not null) then
    raise exception 'inbox not set up' using errcode = 'P0001';
  end if;
  if thread_token !~ '^[0-9a-f]{64}$' or blob !~ '^[A-Za-z0-9_-]+$' then
    raise exception 'bad message' using errcode = '22023';
  end if;
  if (select count(*) from public.thread_messages where not from_owner and created_at > now() - interval '1 minute') >= 20 then
    raise exception 'too many messages, try again in a minute' using errcode = 'P0001';
  end if;
  tid := encode(sha256(decode(thread_token, 'hex')), 'hex');
  if not exists (select 1 from public.threads where id = tid) then
    if envelope is null or envelope !~ '^[A-Za-z0-9_-]+$' then
      raise exception 'bad message' using errcode = '22023';
    end if;
    insert into public.threads (id, envelope) values (tid, envelope);
  elsif (select count(*) from public.thread_messages where thread_id = tid) >= 500 then
    raise exception 'this conversation is full' using errcode = 'P0001';
  end if;
  insert into public.thread_messages (thread_id, from_owner, blob) values (tid, false, blob);
  update public.threads set last_at = now(), last_from_owner = false where id = tid;
end;
$$;

-- Public: a visitor reads their own conversation.
create function public.get_thread(thread_token text) returns json
language plpgsql stable security definer set search_path = '' as $$
declare tid text;
begin
  if thread_token !~ '^[0-9a-f]{64}$' then
    raise exception 'bad token' using errcode = '22023';
  end if;
  tid := encode(sha256(decode(thread_token, 'hex')), 'hex');
  return coalesce((
    select json_agg(json_build_object('id', id, 'from_owner', from_owner, 'created_at', created_at, 'blob', blob) order by created_at, id)
    from public.thread_messages where thread_id = tid), '[]'::json);
end;
$$;

-- Owner: everything needed to read the inbox, as conversations with the
-- most recently active first.
create function public.open_inbox(token text) returns json
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public._owner_ok(token) then
    raise exception 'wrong passphrase' using errcode = '28000';
  end if;
  return json_build_object(
    'wrapped_key', (select wrapped_key from public.inbox where id = 1),
    'threads', coalesce((
      select json_agg(json_build_object(
          'id', t.id, 'envelope', t.envelope, 'created_at', t.created_at, 'last_at', t.last_at,
          'last_from_owner', t.last_from_owner,
          'messages', (select json_agg(json_build_object('id', m.id, 'from_owner', m.from_owner, 'created_at', m.created_at, 'blob', m.blob) order by m.created_at, m.id)
                       from public.thread_messages m where m.thread_id = t.id))
        order by t.last_at desc)
      from public.threads t), '[]'::json));
end;
$$;

-- Owner: reply in a conversation.
create function public.reply_to_thread(token text, thread_id text, blob text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public._owner_ok(token) then
    raise exception 'wrong passphrase' using errcode = '28000';
  end if;
  if blob !~ '^[A-Za-z0-9_-]+$' or not exists (select 1 from public.threads t where t.id = reply_to_thread.thread_id) then
    raise exception 'bad message' using errcode = '22023';
  end if;
  insert into public.thread_messages (thread_id, from_owner, blob) values (reply_to_thread.thread_id, true, blob);
  update public.threads t set last_at = now(), last_from_owner = true where t.id = reply_to_thread.thread_id;
end;
$$;

-- Owner: remove a whole conversation.
create function public.delete_thread(token text, thread_id text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public._owner_ok(token) then
    raise exception 'wrong passphrase' using errcode = '28000';
  end if;
  delete from public.threads t where t.id = delete_thread.thread_id;
end;
$$;

revoke all on function public.get_inbox(), public.setup_inbox(text, text, text, text, text),
  public.send_message(text), public.open_inbox(text), public.delete_message(text, bigint),
  public.change_passphrase(text, text, text, text), public.send_to_thread(text, text, text),
  public.get_thread(text), public.reply_to_thread(text, text, text), public.delete_thread(text, text) from public;
grant execute on function public.get_inbox(), public.setup_inbox(text, text, text, text, text),
  public.open_inbox(text), public.delete_message(text, bigint), public.change_passphrase(text, text, text, text),
  public.send_to_thread(text, text, text), public.get_thread(text), public.reply_to_thread(text, text, text),
  public.delete_thread(text, text) to anon, authenticated;

-- Then, to let the owner claim the inbox, store the hash of a one-time code:
--   insert into public.inbox (id, setup_code_hash)
--   values (1, encode(sha256(convert_to('<CODE>', 'UTF8')), 'hex'));
