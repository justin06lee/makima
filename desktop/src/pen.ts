// What the eye and the wordmark share: a seeded random source, so the same
// seed always draws the same picture, and number formatting that keeps SVG
// paths short.

/** mulberry32: small, fast, and the same sequence everywhere for a seed. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** One decimal place: finer than any screen shows at these sizes. */
export const f = (n: number) => Math.round(n * 10) / 10;
