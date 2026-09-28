// The faces a device can wear, and where each one comes from.
//
// Manga panels, black and white like the rest of the window. They are not
// in git: they are pages of Chainsaw Man — © Tatsuki Fujimoto / Shueisha —
// and this repository is public, so scripts/avatars.ts fetches each from the
// Chainsaw Man wiki, crops it and takes out any colour into src/avatars/ when
// the app is built. Without them the picker offers an upload and every
// device shows its initial instead.
//
// crop is [centre x, centre y, side]: the centre as fractions of the image's
// width and height, the side of the square as a fraction of its height.

export type Character = { id: string; name: string; crop: [number, number, number]; url: string };

export const CHARACTERS: Character[] = [
  { id: "makima", name: "Makima", crop: [0.52, 0.34, 0.62], url: "https://static.wikia.nocookie.net/chainsaw-man/images/6/66/Makima_tells_Denji_the_type_of_boys_she_likes.png/revision/latest?cb=20230409100539" },
  { id: "denji", name: "Denji", crop: [0.37, 0.42, 0.7], url: "https://static.wikia.nocookie.net/chainsaw-man/images/5/52/Denji_believes_he_doesn%27t_deserve_to_have_a_family.png/revision/latest?cb=20241205234656" },
  { id: "power", name: "Power", crop: [0.4, 0.42, 0.72], url: "https://static.wikia.nocookie.net/chainsaw-man/images/e/ed/Power_tells_Aki_that_she_wants_human_blood.png/revision/latest?cb=20230530170652" },
  { id: "aki", name: "Aki", crop: [0.33, 0.19, 0.4], url: "https://static.wikia.nocookie.net/chainsaw-man/images/d/de/Aki%27s_missing_left_arm.png/revision/latest?cb=20230523181152" },
  { id: "pochita", name: "Pochita", crop: [0.565, 0.25, 0.4], url: "https://static.wikia.nocookie.net/chainsaw-man/images/9/96/Pochita_tells_Power_to_help_save_Denji.png/revision/latest?cb=20230411172213" },
  { id: "himeno", name: "Himeno", crop: [0.42, 0.22, 0.46], url: "https://static.wikia.nocookie.net/chainsaw-man/images/a/a0/Himeno_explaining_her_Ghost_Devil_contract.png/revision/latest?cb=20230610052439" },
  { id: "kobeni", name: "Kobeni", crop: [0.64, 0.47, 0.72], url: "https://static.wikia.nocookie.net/chainsaw-man/images/f/f7/Kobeni_slowly_breaking_down.png/revision/latest?cb=20230610050521" },
  { id: "kishibe", name: "Kishibe", crop: [0.44, 0.31, 0.56], url: "https://static.wikia.nocookie.net/chainsaw-man/images/e/ed/Kishibe_tells_Denji_and_Power_that_he%27ll_make_them_stronger.png/revision/latest?cb=20230418191514" },
  { id: "angel", name: "Angel", crop: [0.47, 0.27, 0.42], url: "https://static.wikia.nocookie.net/chainsaw-man/images/c/c7/Angel_eating_at_a_restaurant.png/revision/latest?cb=20230813193819" },
  { id: "reze", name: "Reze", crop: [0.3, 0.45, 0.66], url: "https://static.wikia.nocookie.net/chainsaw-man/images/2/26/Reze_tells_Denji_she_thinks_he%27s_funny.png/revision/latest?cb=20240903063339" },
  { id: "beam", name: "Beam", crop: [0.58, 0.42, 0.56], url: "https://static.wikia.nocookie.net/chainsaw-man/images/7/75/Denji_meets_Beam.png/revision/latest?cb=20230507114849" },
  { id: "galgali", name: "Galgali", crop: [0.4, 0.21, 0.3], url: "https://static.wikia.nocookie.net/chainsaw-man/images/4/48/Violence_Fiend.png/revision/latest?cb=20220806080753" },
  { id: "katana", name: "Katana Man", crop: [0.62, 0.2, 0.4], url: "https://static.wikia.nocookie.net/chainsaw-man/images/4/4b/Katana_Man_as_human.png/revision/latest?cb=20230417043751" },
  { id: "quanxi", name: "Quanxi", crop: [0.64, 0.28, 0.44], url: "https://static.wikia.nocookie.net/chainsaw-man/images/e/e0/Quanxi_contacts_Public_Safety_on_the_mission.png/revision/latest?cb=20240902230152" },
  { id: "asa", name: "Asa", crop: [0.53, 0.4, 0.74], url: "https://static.wikia.nocookie.net/chainsaw-man/images/c/ca/Asa_mugshot.png/revision/latest?cb=20240405085906" },
  { id: "yoru", name: "Yoru", crop: [0.45, 0.24, 0.32], url: "https://static.wikia.nocookie.net/chainsaw-man/images/5/5e/Yoru_laughing_at_the_misery_of_a_civilian.png/revision/latest?cb=20250904183205" },
  { id: "yoshida", name: "Yoshida", crop: [0.47, 0.5, 0.95], url: "https://static.wikia.nocookie.net/chainsaw-man/images/b/b2/Yoshida_stares_at_Fami_from_the_ground.png/revision/latest?cb=20230422094453" },
  { id: "nayuta", name: "Nayuta", crop: [0.52, 0.48, 0.58], url: "https://static.wikia.nocookie.net/chainsaw-man/images/8/86/Nayuta_biting_Denji%27s_finger.png/revision/latest?cb=20230405002016" },
  { id: "fami", name: "Fami", crop: [0.52, 0.55, 0.8], url: "https://static.wikia.nocookie.net/chainsaw-man/images/3/3f/Fami_Closeup.png/revision/latest?cb=20240210115651" },
  { id: "santa", name: "Santa Claus", crop: [0.45, 0.2, 0.3], url: "https://static.wikia.nocookie.net/chainsaw-man/images/1/13/Doll_Devil.png/revision/latest?cb=20200505105107" },
];
