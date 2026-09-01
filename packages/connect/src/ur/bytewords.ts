import { concatBytes, u32be } from '../core/bytes';
import { EraSdkError } from '../core/errors';
import { crc32 } from './crc32';

/**
 * Bytewords codec (minimal style only), per BCR-2020-012.
 *
 * Decode hardening (each of these used to turn malformed input into plausible
 * bytes in naive implementations):
 *  - a letter pair that is not a byteword is a refusal, never a fallback byte;
 *  - a body shorter than the four CRC words plus one byte is a refusal;
 *  - the trailing CRC32 (big-endian) is verified and stripped.
 *
 * The checksum is unkeyed and is not an authentication control — whoever
 * prints the QR prints the CRC too. What it buys is that garbage stops being
 * accepted as data, which frame dedup and reassembly downstream both assume.
 */

const BYTE_WORDS =
  'ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom';

const DIM = 26;
const A = 'a'.charCodeAt(0);

/** Lookup keyed on (first letter, last letter); -1 = not a byteword. */
const LOOKUP: Int16Array = (() => {
  const table = new Int16Array(DIM * DIM).fill(-1);
  for (let i = 0; i < 256; i++) {
    const word = BYTE_WORDS.slice(i * 4, i * 4 + 4);
    const x = word.charCodeAt(0) - A;
    const y = word.charCodeAt(3) - A;
    table[y * DIM + x] = i;
  }
  return table;
})();

export function bytewordsEncode(data: Uint8Array): string {
  const buf = concatBytes(data, u32be(crc32(data)));
  let out = '';
  for (const byte of buf) {
    const word = BYTE_WORDS.slice(byte * 4, byte * 4 + 4);
    out += word[0]! + word[3]!;
  }
  return out;
}

export function bytewordsDecode(body: string): Uint8Array {
  if (body.length % 2 !== 0) {
    throw new EraSdkError('malformed-bytewords', 'bytewords: odd number of letters');
  }
  const words = new Uint8Array(body.length / 2);
  for (let i = 0; i < words.length; i++) {
    const x = body.charCodeAt(i * 2) - A;
    const y = body.charCodeAt(i * 2 + 1) - A;
    if (x < 0 || x >= DIM || y < 0 || y >= DIM) {
      throw new EraSdkError('malformed-bytewords', 'bytewords: letter out of range');
    }
    const value = LOOKUP[y * DIM + x]!;
    if (value < 0) {
      throw new EraSdkError('malformed-bytewords', 'bytewords: not a byteword');
    }
    words[i] = value;
  }
  if (words.length < 5) {
    throw new EraSdkError(
      'malformed-bytewords',
      'bytewords: shorter than a checksum plus one byte',
    );
  }
  const bodyBytes = words.slice(0, words.length - 4);
  const declared =
    ((words[words.length - 4]! << 24) |
      (words[words.length - 3]! << 16) |
      (words[words.length - 2]! << 8) |
      words[words.length - 1]!) >>>
    0;
  if (crc32(bodyBytes) !== declared) {
    throw new EraSdkError('checksum-mismatch', 'bytewords: checksum mismatch');
  }
  return bodyBytes;
}
