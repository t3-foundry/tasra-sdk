// No deployment needed. These public demo keys must never protect real data.
import {offlineRoundTrip} from './offline.ts'

const message = offlineRoundTrip()
if (message !== 'Hello Tasra') throw new Error('Offline round trip failed')
console.log(message)
