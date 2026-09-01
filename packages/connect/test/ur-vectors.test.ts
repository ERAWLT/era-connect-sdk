import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../src/core/bytes';
import { UrDecoder } from '../src/ur/decoder';
import { UrFountainEncoder } from '../src/ur/encoder';
import { Ur } from '../src/ur/ur';

/**
 * Canonical BCR-2020-005 vectors. The 20-frame sequence pins the whole wire
 * stack at once: sha256 seeding, Xoshiro256**, the alias-method degree
 * chooser, the draw-without-replacement shuffle, XOR mixing, bytewords and
 * CRC32. A single differing character means a device cannot decode us.
 */

const SINGLE_PART_CBOR =
  '5832916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba44f7f04f2de44f42d84c374a0e149136f25b018';
const SINGLE_PART_UR =
  'ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch';

const MULTI_PART_CBOR =
  '590100916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3ec4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f595e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff173f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d';

const MULTI_PART_FRAMES = [
  'ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh',
  'ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz',
  'ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol',
  'ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas',
  'ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf',
  'ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp',
  'ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy',
  'ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk',
  'ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny',
  'ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs',
  'ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk',
  'ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs',
  'ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd',
  'ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt',
  'ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt',
  'ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd',
  'ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce',
  'ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy',
  'ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo',
  'ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot',
];

describe('BCR-2020-005 reference vectors', () => {
  it('decodes and re-encodes the single-part vector', () => {
    const decoder = new UrDecoder();
    expect(decoder.receivePart(SINGLE_PART_UR)).toBe(true);
    const ur = decoder.result();
    expect(ur.type).toBe('bytes');
    expect(bytesToHex(ur.cbor)).toBe(SINGLE_PART_CBOR);
    expect(ur.toWireString()).toBe(SINGLE_PART_UR.toUpperCase());
  });

  it('assembles the multi-part vector from its first 9 frames', () => {
    const decoder = new UrDecoder();
    let complete = false;
    for (const frame of MULTI_PART_FRAMES) {
      complete = decoder.receivePart(frame);
      if (complete) break;
    }
    expect(complete).toBe(true);
    expect(bytesToHex(decoder.result().cbor)).toBe(MULTI_PART_CBOR);
  });

  it('re-emits the exact 20 canonical frames (fountain PRNG pinned bit-for-bit)', () => {
    const encoder = new UrFountainEncoder(new Ur('bytes', hexToBytes(MULTI_PART_CBOR)), 30, 10);
    expect(encoder.fragmentCount).toBe(9);
    for (const frame of MULTI_PART_FRAMES) {
      expect(encoder.nextPart().toLowerCase()).toBe(frame);
    }
  });

  it('assembles out of order and with duplicates/losses (fountain property)', () => {
    const decoder = new UrDecoder();
    // Drop the first four source frames entirely; feed the tail + fountain
    // frames, shuffled deterministically, with duplicates.
    const frames = [...MULTI_PART_FRAMES.slice(4), ...MULTI_PART_FRAMES.slice(9)];
    frames.reverse();
    let complete = false;
    for (const frame of frames) {
      complete = decoder.receivePart(frame) || complete;
    }
    expect(complete).toBe(true);
    expect(bytesToHex(decoder.result().cbor)).toBe(MULTI_PART_CBOR);
  });
});
