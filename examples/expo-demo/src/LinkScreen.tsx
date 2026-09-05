import type { EraAccounts, EraConnect } from '@hwlt/era-connect';
import { WALLET_UR_TYPES } from '@hwlt/era-connect';
import { useMemo, useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { UrScannerView } from './UrScannerView';

/** Step 1: scan the device's "connect" QR, derive addresses locally. */
export function LinkScreen(props: {
  era: EraConnect;
  accounts: EraAccounts | null;
  onLinked: (accounts: EraAccounts) => void;
}) {
  // Every UR type a device links with, not just the multichain export — a TON
  // link arrives as a standalone `crypto-hdkey` and a literal list refuses it.
  const scanner = useMemo(() => props.era.scanner({ expectedTypes: WALLET_UR_TYPES }), [props.era]);
  const [error, setError] = useState<string | null>(null);
  const accounts = props.accounts;

  if (accounts) {
    const evm = accounts.evm();
    const btc = accounts.btc();
    const tron = accounts.tron();
    const sol = accounts.solana();
    return (
      <ScrollView contentContainerStyle={styles.list}>
        <Text style={styles.h1}>Linked: {accounts.device.name ?? 'ERA Wallet'}</Text>
        <Row label="Firmware" value={accounts.device.firmwareVersion ?? '—'} />
        <Row label="Master fingerprint" value={accounts.masterFingerprint} />
        {evm && <Row label="EVM #0" value={evm.deriveAddress(0)} />}
        {btc && <Row label="Bitcoin #0" value={btc.deriveAddress(0)} />}
        {sol[0] && <Row label="Solana #0" value={sol[0].address} />}
        {tron && <Row label="Tron #0" value={tron.deriveAddress(0)} />}
        <Text style={styles.hint}>
          All addresses were derived locally from the export — the device is not needed again until
          something must be signed.
        </Text>
      </ScrollView>
    );
  }

  return (
    <View style={styles.wrap}>
      <Text style={styles.h1}>Open Connect / sync on the device and scan it</Text>
      <UrScannerView
        scanner={scanner}
        onComplete={(ur) => {
          try {
            props.onLinked(props.era.parseAccounts(ur));
          } catch (e) {
            setError(String(e));
          }
        }}
      />
      {error ? <Text style={styles.error}>{error}</Text> : null}
    </View>
  );
}

function Row(props: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{props.label}</Text>
      <Text style={styles.value} numberOfLines={1}>
        {props.value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { flex: 1, padding: 16, gap: 12 },
  list: { padding: 16, gap: 10 },
  h1: { color: 'white', fontSize: 16, fontWeight: '700' },
  row: { backgroundColor: '#161a20', borderRadius: 10, padding: 12, gap: 4 },
  label: { color: '#5c6570', fontSize: 12 },
  value: { color: 'white', fontFamily: 'Courier', fontSize: 13 },
  hint: { color: '#5c6570', fontSize: 12, marginTop: 8 },
  error: { color: '#ff6b6b', fontSize: 12 },
});
