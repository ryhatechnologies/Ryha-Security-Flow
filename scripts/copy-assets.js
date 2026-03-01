const fs = require('fs');
const path = require('path');

// Create dist/ui directory if it doesn't exist
const distUiDir = path.join(__dirname, '../dist/ui');
if (!fs.existsSync(distUiDir)) {
  fs.mkdirSync(distUiDir, { recursive: true });
}

// Copy index.html
const srcFile = path.join(__dirname, '../src/ui/index.html');
const destFile = path.join(distUiDir, 'index.html');

try {
  fs.copyFileSync(srcFile, destFile);
  console.log('✅ Assets copied successfully');
} catch (error) {
  console.error('❌ Failed to copy assets:', error.message);
  process.exit(1);
}
