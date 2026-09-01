import type { AnimatedUr } from '@era-wallet/connect';
import { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import QRCode from 'react-native-qrcode-svg';

/**
 * Copy-pasteable animated-QR renderer: one interval, one QR component.
 * 125 ms (8 fps) and the SDK's 180-byte fragments are the device-proven
 * defaults — keep the SAME AnimatedUr instance mounted for the whole review.
 */
export function AnimatedQrView(props: { animated: AnimatedUr }) {
  const [frame, setFrame] = useState(() => props.animated.nextFrame());

  useEffect(() => {
    if (props.animated.isSingleFrame) return;
    const timer = setInterval(() => setFrame(props.animated.nextFrame()), 125);
    return () => clearInterval(timer);
  }, [props.animated]);

  return (
    <View style={styles.wrap}>
      <View style={styles.card}>
        <QRCode value={frame} size={260} backgroundColor="white" />
      </View>
      <Text style={styles.caption}>
        {props.animated.isSingleFrame
          ? 'Single frame'
          : `Animating ${props.animated.fragmentCount} fragments · ${props.animated.urType}`}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { alignItems: 'center', gap: 8 },
  card: { backgroundColor: 'white', padding: 16, borderRadius: 14 },
  caption: { color: '#5c6570', fontSize: 12 },
});
