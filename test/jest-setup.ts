// Mock uuid module to avoid ESM issues
// Generate valid UUIDs for testing
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

jest.mock('uuid', () => ({
  v4: jest.fn(() => generateUUID()),
  v1: jest.fn(() => generateUUID()),
  v3: jest.fn(() => generateUUID()),
  v5: jest.fn(() => generateUUID()),
}));

// Mock HandlebarsAdapter to avoid native module loading issues
jest.mock('@nestjs-modules/mailer/dist/adapters/handlebars.adapter', () => ({
  HandlebarsAdapter: jest.fn().mockImplementation(() => ({
    compile: jest.fn(),
  })),
}));

// Mock passport-google-oauth20 to avoid OAuth2Strategy initialization issues
jest.mock('passport-google-oauth20', () => {
  const mockStrategy = jest.fn().mockImplementation(function(options, verify) {
    this.name = 'google';
    this.authenticate = jest.fn();
  });
  
  return {
    Strategy: mockStrategy,
  };
});

