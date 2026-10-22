// Site settings. Everything here is public by design: the publishable key
// only lets visitors call the database functions in supabase/schema.sql,
// which never return anything readable without the owner's passphrase.
window.SM_CONFIG = {
  supabaseUrl: "https://cvtubojvdqnfaxthbjsc.supabase.co",
  supabaseKey: "sb_publishable_VIDa3Aoa6OBoSK87v3ICNA_bislZEnm",
  // The inbox's public key. Senders encrypt to this key and refuse any other,
  // so even someone who took over the database couldn't swap in their own.
  // If the inbox is ever set up again, put the new key here.
  pinnedPublicKey: "BJ2A01bvvqFUnwDsfYnZu6Yi4cCUvbsf2sywVc5WFKkD3vTsUS_mYFzv40_DEl2Ouw6aTMvddbOoAxO5WHU7Ctg",
};
