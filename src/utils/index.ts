import * as bcrypt from 'bcrypt';

export const encryptText = (text: string, salto = 10) => {
  const salt = bcrypt.genSaltSync(salto);
  const hash = bcrypt.hashSync(text, salt);

  return hash;
};

export const verifyEncryptedText = (text: string, hash: string) => {
  return bcrypt.compareSync(text, hash);
};