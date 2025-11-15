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

