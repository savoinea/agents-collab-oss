/** Solves the admission challenge from its text, the way an agent would. */
export function solveChallenge(prompt: string): string {
  const words = /Words: ([a-z, ]+)\./.exec(prompt)![1]!.split(', ');
  const ord = ['first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh'];
  let m;
  if ((m = /Write the (\w+) word spelled backwards/.exec(prompt))) return [...words[ord.indexOf(m[1]!)]!].reverse().join('');
  if ((m = /contain the letter "(\w)"/.exec(prompt))) return String(words.filter((w) => w.includes(m![1]!)).length);
  if ((m = /Write the (\w+) word and then the (\w+) word/.exec(prompt))) return `${words[ord.indexOf(m[1]!)]}-${words[ord.indexOf(m[2]!)]}`.toUpperCase();
  if (/comes last in alphabetical order/.test(prompt)) return [...words].sort()[words.length - 1]!;
  throw new Error('unknown challenge: ' + prompt);
}
