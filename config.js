// Site settings. Everything here is public by design: the publishable key
// only lets visitors call the database functions in supabase/schema.sql,
// which never return anything readable without the owner's passphrase.
window.SM_CONFIG = {
  supabaseUrl: "https://cvtubojvdqnfaxthbjsc.supabase.co",
  supabaseKey: "sb_publishable_VIDa3Aoa6OBoSK87v3ICNA_bislZEnm",
  // Once the inbox is set up, paste its public key here (the inbox page shows
  // it). Senders then encrypt to this key and refuse any other, so even
  // someone who took over the database couldn't swap in their own key.
  pinnedPublicKey: "",
};
