const AGENT_ADJECTIVES =
  "quiet young old small large clever brave gentle happy lucky merry proud quick slow sleepy curious careful friendly watchful nimble patient eager bold calm wild wise kind keen swift sturdy loyal cheerful".split(
    " ",
  );

const OBJECT_ADJECTIVES =
  "silver golden copper amber scarlet violet indigo hazel old new small large round square narrow wide smooth bright warm cool soft light dark painted carved empty full tiny ancient fine rare precious".split(
    " ",
  );

const PLACE_ADJECTIVES =
  "old ancient quiet busy sleepy secret hidden narrow wide deep high low wild calm bright dark early late northern southern eastern western green ruined grand little great warm cool cold sunny shadowy".split(
    " ",
  );

const AGENTS =
  "otter fox owl rabbit badger heron mouse deer goat horse whale dolphin seal turtle falcon sparrow robin raven cat dog baker sailor pilot gardener painter potter weaver keeper driver teacher doctor farmer fisher hunter dancer singer writer reader walker climber swimmer rider builder trader merchant courier captain guide scout warden smith carpenter mason tailor brewer cook nurse clerk poet".split(
    " ",
  );

const VERBS = "carries finds holds keeps hides seeks saves brings".split(" ");

const OBJECTS =
  "key lantern coin map letter bottle basket blanket camera compass ticket ribbon pebble shell book cup spoon hat scarf glove boot bell candle mirror brush comb rope net sail oar wheel anchor flag drum flute violin clock watch ring bracelet necklace badge medal pencil notebook envelope stamp parcel box crate jar pot pan kettle teapot plate bowl knife fork towel pillow cushion curtain rug".split(
    " ",
  );

const PLACES =
  "bridge river garden forest harbor valley hill cabin market tower meadow island station orchard tunnel lighthouse village castle beach cliff cave lake pond stream field farm mill barn cottage chapel plaza alley street road path gate park pier dock port quarry ridge slope summit canyon desert oasis spring well court yard roof attic cellar kitchen library museum theater studio gallery workshop factory warehouse greenhouse".split(
    " ",
  );

const PREPOSITIONS = "under near beside beyond behind past around above".split(
  " ",
);

/**
 * A grammatical phrase with about 39 bits of choice entropy. That is lower
 * than six independent 256-word picks, but PBKDF2-SHA256 at 600k rounds makes
 * offline guessing expensive. Rejection sampling avoids modulo bias.
 */
export function generatePassphrase(): string {
  const objectAdjective = pick(OBJECT_ADJECTIVES);
  return [
    pick(AGENT_ADJECTIVES),
    pick(AGENTS),
    pick(VERBS),
    /^[aeiou]/.test(objectAdjective) ? "an" : "a",
    objectAdjective,
    pick(OBJECTS),
  ].join(" ");
}

function pick(words: readonly string[]): string {
  return words[randomIndex(words.length)] ?? "quiet";
}

function randomIndex(max: number): number {
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  const buffer = new Uint32Array(1);
  let value = 0;
  do {
    globalThis.crypto.getRandomValues(buffer);
    value = buffer[0] ?? 0;
  } while (value >= limit);
  return value % max;
}
