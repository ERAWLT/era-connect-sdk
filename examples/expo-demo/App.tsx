// CSPRNG polyfill MUST be the first import (request ids need it).
import 'react-native-get-random-values';

import type { EraAccounts } from '@hwlt/era-connect';
import { EraConnect } from '@hwlt/era-connect';
import { StatusBar } from 'expo-status-bar';
import { useMemo, useState } from 'react';
import { SafeAreaView, StyleSheet, Text, TouchableOpacity, View } from 'react-native';
import { LinkScreen } from './src/LinkScreen';
import { SignScreen } from './src/SignScreen';

/**
 * ERA Connect demo: link a device, then sign a message — fully OFFLINE.
 * The SDK performs no network I/O and neither does this app; everything you
 * see travels over the camera and the QR codes.
 */
export default function App() {
  const era = useMemo(() => new EraConnect({ origin: 'ERA Connect Demo' }), []);
  const [accounts, setAccounts] = useState<EraAccounts | null>(null);
  const [tab, setTab] = useState<'link' | 'sign'>('link');

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar style="light" />
      <View style={styles.tabs}>
        <Tab label="1 · Link" active={tab === 'link'} onPress={() => setTab('link')} />
        <Tab label="2 · Sign" active={tab === 'sign'} onPress={() => accounts && setTab('sign')} />
      </View>
      {tab === 'link' ? (
        <LinkScreen
          era={era}
          accounts={accounts}
          onLinked={(linked) => {
            setAccounts(linked);
            setTab('sign');
          }}
        />
      ) : accounts ? (
        <SignScreen era={era} accounts={accounts} />
      ) : null}
    </SafeAreaView>
  );
}

function Tab(props: { label: string; active: boolean; onPress: () => void }) {
  return (
    <TouchableOpacity
      style={[styles.tab, props.active && styles.tabActive]}
      onPress={props.onPress}
    >
      <Text style={styles.tabText}>{props.label}</Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0b0d10' },
  tabs: { flexDirection: 'row', padding: 12, gap: 8 },
  tab: { flex: 1, padding: 12, borderRadius: 10, backgroundColor: '#161a20', alignItems: 'center' },
  tabActive: { backgroundColor: '#25406b' },
  tabText: { color: 'white', fontWeight: '600' },
});
