const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function shouldUseRustServer() {
  return (
    process.env.VIBETUNNEL_USE_RUST_SERVER === '1' ||
    process.env.VIBETUNNEL_USE_RUST_SERVER === 'true' ||
    process.argv.includes('--rust-server')
  );
}

console.log('Starting CI build process...');

// Ensure directories exist
console.log('Creating directories...');
execSync('node scripts/ensure-dirs.js', { stdio: 'inherit' });

// Copy assets
console.log('Copying assets...');
execSync('node scripts/copy-assets.js', { stdio: 'inherit' });

// Build CSS
console.log('Building CSS...');
execSync('pnpm exec postcss ./src/client/styles.css -o ./public/bundle/styles.css', { stdio: 'inherit' });

// Bundle client JavaScript
console.log('Bundling client JavaScript...');
execSync('esbuild src/client/app-entry.ts --bundle --outfile=public/bundle/client-bundle.js --format=esm --minify --define:process.env.NODE_ENV=\'"production"\'', { stdio: 'inherit' });
execSync('esbuild src/client/test-entry.ts --bundle --outfile=public/bundle/test.js --format=esm --minify --define:process.env.NODE_ENV=\'"production"\'', { stdio: 'inherit' });
execSync('esbuild src/client/sw.ts --bundle --outfile=public/sw.js --format=iife --minify --define:process.env.NODE_ENV=\'"production"\'', { stdio: 'inherit' });

const useRustServer = shouldUseRustServer();

if (useRustServer) {
  console.log('Building Rust server...');
  execSync('cargo build --release --manifest-path rust-server/Cargo.toml', { stdio: 'inherit' });

  const rustBinary = path.join(__dirname, '..', 'rust-server', 'target', 'release', 'vibetunnel-rs');
  if (!fs.existsSync(rustBinary)) {
    console.error('ERROR: rust-server/target/release/vibetunnel-rs not found after cargo build!');
    process.exit(1);
  }

  const nativeDir = path.join(__dirname, '..', 'native');
  fs.mkdirSync(nativeDir, { recursive: true });
  fs.copyFileSync(rustBinary, path.join(nativeDir, 'vibetunnel-rs'));
  fs.chmodSync(path.join(nativeDir, 'vibetunnel-rs'), 0o755);
} else {
  // Build server TypeScript
  console.log('Building server...');
  // Force a clean build in CI to avoid incremental build issues
  execSync('npx tsc --build --force', { stdio: 'inherit' });

  // Verify dist directory exists
  if (fs.existsSync(path.join(__dirname, '../dist'))) {
    const files = fs.readdirSync(path.join(__dirname, '../dist'));
    console.log(`Server build created ${files.length} files in dist/`);
    console.log('Files in dist:', files.join(', '));

    // Check for the essential server.js file
    if (!fs.existsSync(path.join(__dirname, '../dist/server/server.js'))) {
      console.error('ERROR: dist/server/server.js not found after tsc build!');
      console.log('Contents of dist directory:');
      execSync('find dist -type f | head -20', { stdio: 'inherit', cwd: path.join(__dirname, '..') });
      process.exit(1);
    }
  } else {
    console.error('ERROR: dist directory does not exist after tsc build!');
    process.exit(1);
  }
}

// Build zig forwarder first.
// build-native.js verifies the forwarder in CI.
console.log('Building zig forwarder...');
if (useRustServer) {
  execSync('VIBETUNNEL_USE_RUST_SERVER=1 node scripts/build-fwd-zig.js', { stdio: 'inherit' });
} else {
  execSync('node scripts/build-fwd-zig.js', { stdio: 'inherit' });
}

if (useRustServer) {
  console.log('Skipping Node SEA build in CI for Rust server mode.');
  console.log('CI build completed successfully!');
  process.exit(0);
}

// Build native executable in CI
console.log('Building native executable for CI...');
execSync('node build-native.js', { stdio: 'inherit' });

console.log('CI build completed successfully!');
