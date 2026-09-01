import type { EraAccounts, EraConnect, SignRequest } from '@hwlt/era-connect';
import { utf8Encode } from '@hwlt/era-connect';
import type { EvmSignatureResult } from '@hwlt/era-connect/evm';
import { EvmChain } from '@hwlt/era-connect/evm';
import { verifyEvmSignature } from '@hwlt/era-connect/verify';
import { useMemo, useState } from 'react';
import { Button, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { AnimatedQrView } from './AnimatedQrView';
import { UrScannerView } from './UrScannerView';

/**
 * Step 2: personal_sign round trip — build request → animated QR → device
 * approves → scan reply → verify the recovered address. Fully offline.
 */
export function SignScreen(props: { era: EraConnect; accounts: EraAccounts }) {
  const evm = props.accounts.evm();
  const [message, setMessage] = useState('Hello from ERA Connect');
  const [request, setRequest] = useState<SignRequest<EvmSignatureResult> | null>(null);
  const [phase, setPhase] = useState<'compose' | 'show' | 'scan' | 'done'>('compose');
  const [outcome, setOutcome] = useState<string | null>(null);

  if (!evm) {
    return <Text style={styles.error}>The linked wallet carries no EVM account.</Text>;
  }
  const address = evm.deriveAddress(0);
  // utf8Encode works on every Hermes version (TextEncoder landed only in RN 0.74).
  const signData = utf8Encode(message);

  const start = () => {
    setRequest(
      props.era.evm.generateSignRequest({
        signData,
        dataType: EvmChain.DataType.personalMessage,
        path: evm.pathFor(0),
        xfp: evm.xfp,
        address,
      }),
    );
    setPhase('show');
  };

  return (
    <ScrollView contentContainerStyle={styles.wrap}>
      {phase === 'compose' && (
        <View style={styles.block}>
          <Text style={styles.h1}>Sign a message with {address.slice(0, 10)}…</Text>
          <TextInput style={styles.input} value={message} onChangeText={setMessage} />
          <Button title="Build sign request" onPress={start} />
        </View>
      )}

      {phase === 'show' && request && (
        <ShowPhase request={request} onApproved={() => setPhase('scan')} />
      )}

      {phase === 'scan' && request && (
        <ScanPhase
          request={request}
          onDone={(text) => {
            setOutcome(text);
            setPhase('done');
          }}
          signData={signData}
          address={address}
        />
      )}

      {phase === 'done' && <Text style={styles.ok}>{outcome}</Text>}
    </ScrollView>
  );
}

function ShowPhase(props: { request: SignRequest<EvmSignatureResult>; onApproved: () => void }) {
  // ONE AnimatedUr for the whole review — rebuilding it per render restarts
  // the fountain sequence for no reason (and rebuilding the REQUEST would
  // orphan the device's reply).
  const animated = useMemo(() => props.request.toAnimated(), [props.request]);
  return (
    <View style={styles.block}>
      <Text style={styles.h1}>Scan this with the device, review, approve</Text>
      <AnimatedQrView animated={animated} />
      <Button title="Device approved — scan its reply" onPress={props.onApproved} />
    </View>
  );
}

function ScanPhase(props: {
  request: SignRequest<EvmSignatureResult>;
  signData: Uint8Array;
  address: `0x${string}`;
  onDone: (outcome: string) => void;
}) {
  // ONE scanner for the whole phase — it accumulates frames and holds the
  // request-id expectation.
  const scanner = useMemo(() => props.request.scanner(), [props.request]);
  return (
    <View style={[styles.block, styles.grow]}>
      <UrScannerView
        scanner={scanner}
        onComplete={() => {
          try {
            const signature = scanner.parse(); // typed + request-id echo enforced
            const check = verifyEvmSignature({
              signData: props.signData,
              dataType: EvmChain.DataType.personalMessage,
              signature: signature.signature,
              address: props.address,
            });
            props.onDone(
              check.ok
                ? `Verified: the device signed exactly these bytes with ${props.address}`
                : `REFUSED: ${check.reason}`,
            );
          } catch (e) {
            props.onDone(`REFUSED: ${String(e)}`);
          }
        }}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { padding: 16, gap: 12 },
  grow: { minHeight: 420 },
  block: { gap: 12 },
  h1: { color: 'white', fontSize: 16, fontWeight: '700' },
  input: { backgroundColor: '#161a20', color: 'white', borderRadius: 10, padding: 12 },
  ok: { color: '#38d178', fontSize: 14 },
  error: { color: '#ff6b6b', padding: 16 },
});
