// The faces a device can wear, and where each one comes from.
//
// The images are not in git. They are stills from Chainsaw Man — © Tatsuki
// Fujimoto / Shueisha, MAPPA — and this repository is public, so
// scripts/avatars.ts fetches each from the Chainsaw Man wiki and crops it
// into src/avatars/ when the app is built. Without them the picker offers an
// upload and every device shows its initial instead.
//
// crop is [centre x, centre y, side]: the centre as fractions of the image's
// width and height, the side of the square as a fraction of its height.

export type Character = { id: string; name: string; crop: [number, number, number]; url: string };

export const CHARACTERS: Character[] = [
  { id: "makima", name: "Makima", crop: [0.5, 0.55, 0.85], url: "https://static.wikia.nocookie.net/chainsaw-man/images/6/6a/Episode_12-5.png/revision/latest?cb=20221227085333" },
  { id: "denji", name: "Denji", crop: [0.365, 0.33, 0.62], url: "https://static.wikia.nocookie.net/chainsaw-man/images/e/e7/Denji_and_Power_at_Public_Safety_HQ.png/revision/latest?cb=20251209105905" },
  { id: "power", name: "Power", crop: [0.5, 0.45, 0.8], url: "https://static.wikia.nocookie.net/chainsaw-man/images/1/10/Episode_6-2.png/revision/latest?cb=20221115090650" },
  { id: "aki", name: "Aki", crop: [0.5, 0.42, 0.85], url: "https://static.wikia.nocookie.net/chainsaw-man/images/6/6a/Aki_enraged_over_the_deaths_of_Division_2.png/revision/latest?cb=20251209133343" },
  { id: "pochita", name: "Pochita", crop: [0.48, 0.45, 0.78], url: "https://static.wikia.nocookie.net/chainsaw-man/images/f/fe/Episode_1-2.png/revision/latest?cb=20221004092558" },
  { id: "himeno", name: "Himeno", crop: [0.5, 0.45, 0.65], url: "https://static.wikia.nocookie.net/chainsaw-man/images/d/d6/Himeno_horrified_over_seeing_Aki_wounded.png/revision/latest?cb=20240223095845" },
  { id: "kobeni", name: "Kobeni", crop: [0.49, 0.42, 0.62], url: "https://static.wikia.nocookie.net/chainsaw-man/images/5/5e/Kobeni_making_double_peace_sign.png/revision/latest?cb=20221115175448" },
  { id: "kishibe", name: "Kishibe", crop: [0.47, 0.35, 0.6], url: "https://static.wikia.nocookie.net/chainsaw-man/images/6/6e/Episode_7-1.png/revision/latest?cb=20221122095357" },
  { id: "angel", name: "Angel", crop: [0.47, 0.37, 0.62], url: "https://static.wikia.nocookie.net/chainsaw-man/images/5/5f/Episode_12-4.png/revision/latest?cb=20221227085327" },
  { id: "reze", name: "Reze", crop: [0.27, 0.4, 0.7], url: "https://static.wikia.nocookie.net/chainsaw-man/images/e/ee/Denji_realizes_he%27s_starting_to_fall_for_Reze.png/revision/latest?cb=20251209103426" },
  { id: "beam", name: "Beam", crop: [0.62, 0.45, 0.9], url: "https://static.wikia.nocookie.net/chainsaw-man/images/c/c0/Beam_meets_Denji.png/revision/latest?cb=20251209101723" },
  { id: "galgali", name: "Galgali", crop: [0.68, 0.38, 0.6], url: "https://static.wikia.nocookie.net/chainsaw-man/images/1/13/Galgali_beating_some_zombies.png/revision/latest?cb=20221220183700" },
  { id: "katana", name: "Katana Man", crop: [0.45, 0.4, 0.7], url: "https://static.wikia.nocookie.net/chainsaw-man/images/0/04/Katana_Man_human_anime.png/revision/latest?cb=20221129182826" },
  { id: "quanxi", name: "Quanxi", crop: [0.55, 0.14, 0.16], url: "https://static.wikia.nocookie.net/chainsaw-man/images/8/80/Quanxi_infobox.png/revision/latest?cb=20231222204207" },
  { id: "asa", name: "Asa", crop: [0.56, 0.2, 0.25], url: "https://static.wikia.nocookie.net/chainsaw-man/images/9/9b/Volume_20_%28Textless%29.png/revision/latest?cb=20250503033800" },
  { id: "yoru", name: "Yoru", crop: [0.42, 0.2, 0.28], url: "https://static.wikia.nocookie.net/chainsaw-man/images/9/90/Volume_12_%28Textless%29.png/revision/latest?cb=20230405234930" },
  { id: "yoshida", name: "Yoshida", crop: [0.57, 0.18, 0.2], url: "https://static.wikia.nocookie.net/chainsaw-man/images/4/4c/Volume_17_%28Textless%29.png/revision/latest?cb=20250502232859" },
  { id: "nayuta", name: "Nayuta", crop: [0.5, 0.33, 0.3], url: "https://static.wikia.nocookie.net/chainsaw-man/images/9/94/Nayuta_Part_2.png/revision/latest?cb=20230422123541" },
  { id: "fami", name: "Fami", crop: [0.58, 0.23, 0.27], url: "https://static.wikia.nocookie.net/chainsaw-man/images/e/e4/Volume_14_%28Textless%29.png/revision/latest?cb=20250505195335" },
  { id: "santa", name: "Santa Claus", crop: [0.5, 0.2, 0.25], url: "https://static.wikia.nocookie.net/chainsaw-man/images/9/97/Santa_Claus_%28Tolka%27s_Master%29_Infobox.png/revision/latest?cb=20231222204442" },
];
