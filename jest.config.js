module.exports = {
    transform: {
      '^.+\\.[t|j]sx?$': 'babel-jest', // Transform both JS and JSX files
      '^.+\\.mjs$': 'babel-jest' // Ensure .mjs files are also transformed
    },
    // Ensure Jest handles `.mjs` files
    moduleFileExtensions: ['js', 'json', 'jsx', 'node', 'mjs'],
    testMatch: [
      '**/__tests__/**/*.js?(x)',
      '**/?(*.)+(spec|test).js?(x)',
      '**/__tests__/**/*.mjs',
      '**/?(*.)+(spec|test).mjs'
    ],
  };
  