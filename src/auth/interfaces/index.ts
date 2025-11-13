import { SocialProvider } from "../enums/socialProvider.enum";

export interface JwtPayload {
  id: string;
  name: string;
  email: string;
}

export type SocialProviderUser = {
  email: string;
  firstName: string;
  lastName: string;
  picture?: string;
  accessToken?: string;
  refreshToken?: string;
  social_provider: SocialProvider;
};