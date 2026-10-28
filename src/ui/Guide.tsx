export function Guide() {
  return (
    <div class="guide">
      <h2>What changed</h2>
      <p>
        Android developer verification links every app to a verified developer. Since 30 September 2026, on certified devices (Android 7+) in Brazil, Indonesia,
        Singapore and Thailand, apps installed through participating stores (Google Play, Galaxy Store, HONOR App Market, OPPO App Market, Xiaomi GetApps, vivo
        V-Appstore and Palm Store) must be registered to a verified developer. Google plans to extend this to all certified devices in 2027, after which installing
        apps from unverified developers outside those stores needs the deliberately slow "advanced flow" or ADB.
      </p>
      <p>
        So each package name, and <em>every</em> key that signs it, needs registering: your own release key, the key a store re-signs with, keys from older builds
        still in circulation.
      </p>
      <h2>The steps, and where Package Pass helps</h2>
      <ol>
        <li>
          <strong>Verify your identity</strong> in the Android Developer Console (or the developer verification page in Play Console).
        </li>
        <li>
          <strong>List your package names and keys.</strong> Drop every build you distribute: your own release APKs, APKs downloaded back from stores that re-sign,
          bundles, split sets. Package Pass reads the package name and the SHA-256 of the key Android actually checks, follows v3 key rotation, and flags debug keys and
          upload keys.
        </li>
        <li>
          <strong>Register each package and add each key.</strong> Copy fingerprints from the plan, or export the API script, which walks the documented Developer
          Console API calls in dry-run mode until you set <code>RUN=1</code>.
        </li>
        <li>
          <strong>Prove ownership</strong> for existing package names: put the console snippet in <code>assets/adi-registration.properties</code>, sign an APK with
          that key, check it on the <em>Proof APK check</em> tab, then upload. Once a key is verified on one package, the console skips this step for that key on
          your other packages.
        </li>
      </ol>
      <h2>Good to know</h2>
      <ul>
        <li>
          <strong>Play App Signing:</strong> an <code>.aab</code> carries your upload key. Devices see Google's app signing key; copy it from Play Console › App
          integrity.
        </li>
        <li>
          <strong>Stores that re-sign</strong> (some F-Droid builds, other app stores) give your app a different key. Download the store's APK and add that key too.
        </li>
        <li>
          <strong>Key rotation:</strong> Android 9+ verifies with the newest key in the v3 lineage, older devices with the original key.
        </li>
        <li>
          <strong>Privacy:</strong> files are parsed in this tab with WebCrypto. Nothing is uploaded, stored or sent anywhere. The page works offline once loaded.
        </li>
      </ul>
      <p class="muted">
        Sources:{' '}
        <a href="https://developer.android.com/developer-verification/guides" rel="noreferrer" target="_blank">
          Android developer verification guides
        </a>
        ,{' '}
        <a href="https://developer.android.com/developer-verification/reference/developer-console-api" rel="noreferrer" target="_blank">
          Developer Console API reference
        </a>
        . Always confirm against the console. Package Pass is not affiliated with Google.
      </p>
    </div>
  );
}
