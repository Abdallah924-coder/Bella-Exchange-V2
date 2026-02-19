const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'data');

function ensureFile(fileName, initialValue) {
  const filePath = path.join(dataDir, fileName);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(initialValue, null, 2));
  }
  return filePath;
}

function readJSON(fileName, initialValue = []) {
  const filePath = ensureFile(fileName, initialValue);
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJSON(fileName, value) {
  const filePath = ensureFile(fileName, value);
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

module.exports = { readJSON, writeJSON, ensureFile };
