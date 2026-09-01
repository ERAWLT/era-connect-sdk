import type { Ur, UrScanner } from '@era-wallet/connect';
import { CameraView, useCameraPermissions } from 'expo-camera';
import { useRef, useState } from 'react';
import { Button, StyleSheet, Text, View } from 'react-native';

/**
 * Copy-pasteable camera → UrScanner bridge.
 *
 * Everything integration-relevant is in `onBarcodeScanned`: feed EVERY frame,
 * branch on the typed result, surface rejections ONCE via `repeated`.
 */
export function UrScannerView(props: { scanner: UrScanner; onComplete: (ur: Ur) => void }) {
  const [permission, requestPermission] = useCameraPermissions();
  const [progress, setProgress] = useState(0);
  const [note, setNote] = useState<string | null>(null);
  const done = useRef(false);

  if (!permission?.granted) {
    return (
      <View style={styles.center}>
        <Text style={styles.text}>Camera access is needed to scan the device.</Text>
        <Button title="Grant camera access" onPress={requestPermission} />
      </View>
    );
  }

  return (
    <View style={styles.wrap}>
      <CameraView
        style={styles.camera}
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={({ data }) => {
          if (done.current) return;
          const result = props.scanner.receivePart(data);
          switch (result.kind) {
            case 'progress':
              setProgress(result.progress);
              setNote(
                result.framesExpected > 1
                  ? `${result.framesReceived} / ${result.framesExpected} frames`
                  : null,
              );
              break;
            case 'complete':
              done.current = true;
              props.onComplete(result.ur);
              break;
            case 'rejected':
              // A wrong/hostile QR repeats at camera rate; `repeated` keeps it to one line.
              if (result.rejection.repeated === 1) setNote(result.rejection.message);
              break;
            case 'duplicate':
              break; // the camera saw the same frame again — free to ignore
          }
        }}
      />
      <View style={styles.progressTrack}>
        <View style={[styles.progressFill, { width: `${Math.round(progress * 100)}%` }]} />
      </View>
      {note ? <Text style={styles.note}>{note}</Text> : null}
      <Text style={styles.hint}>
        The device animates its reply at 2.5 fps — multi-frame replies take a few seconds.
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { flex: 1, gap: 8 },
  camera: { flex: 1, borderRadius: 14, overflow: 'hidden' },
  progressTrack: { height: 6, borderRadius: 3, backgroundColor: '#161a20' },
  progressFill: { height: 6, borderRadius: 3, backgroundColor: '#4c8dff' },
  note: { color: '#ffb454', fontSize: 12 },
  hint: { color: '#5c6570', fontSize: 12 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 12 },
  text: { color: 'white', textAlign: 'center' },
});
