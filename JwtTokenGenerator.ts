import fs from 'fs';
import path from 'path';
import { importPKCS8, SignJWT } from 'jose';

/**
 * JWT generator for Playwright / TypeScript.
 *
 * Usage:
 *   const token = await JwtTokenGenerator.createBearer(123);
 *
 * Environment variables:
 *   JWT_PRIVATE_KEY_PATH  - Path to PKCS#8 PEM private key
 *   JWT_SETTINGS_PROFILE_ID - Numeric SETTINGS profile id
 *   JWT_ISSUER            - JWT issuer
 *   JWT_SUBJECT           - JWT subject
 *   JWT_EXPIRY_HOURS      - Expiry in hours (default 8)
 */
export class JwtTokenGenerator {
  private static readonly DEFAULT_PRIVATE_KEY_PATH =
    path.resolve(process.cwd(), 'certificates', 'jwt-private-key-pkcs8.pem');

  private static get settingsProfileId(): number {
    const value = process.env.JWT_SETTINGS_PROFILE_ID;
    if (!value) {
      throw new Error(
        'JWT_SETTINGS_PROFILE_ID is not configured. Set it to the numeric value used by Profile.SETTINGS in the Java implementation.'
      );
    }

    const profileId = Number(value);

    if (!Number.isInteger(profileId)) {
      throw new Error('JWT_SETTINGS_PROFILE_ID must be an integer.');
    }

    return profileId;
  }

  private static get issuer(): string {
    return process.env.JWT_ISSUER ?? 'f49426';
  }

  private static get subject(): string {
    return process.env.JWT_SUBJECT ?? 'f49426';
  }

  private static get expiryHours(): number {
    const value = Number(process.env.JWT_EXPIRY_HOURS ?? '8');

    if (!Number.isFinite(value) || value <= 0) {
      throw new Error('JWT_EXPIRY_HOURS must be a positive number.');
    }

    return value;
  }

  /**
   * Generates a Bearer JWT for the supplied application id.
   * Profile is always SETTINGS.
   */
  public static async createBearer(idApp: number): Promise<string> {
    if (!Number.isInteger(idApp) || idApp <= 0) {
      throw new Error('idApp must be a positive integer.');
    }

    const privateKeyPath =
      process.env.JWT_PRIVATE_KEY_PATH ?? this.DEFAULT_PRIVATE_KEY_PATH;

    if (!fs.existsSync(privateKeyPath)) {
      throw new Error(`JWT private key not found: ${privateKeyPath}`);
    }

    const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
    const privateKey = await importPKCS8(privateKeyPem, 'RS256');

    // Equivalent to:
    // Rights.builder()
    //   .appProfilePairs(Collections.singletonList(
    //      AppProfilePair.builder()
    //        .idApp(idApp)
    //        .idProfile(Profile.SETTINGS)
    //        .build()))
    //   .build();
    const rights = {
      appProfilePairs: [
        {
          idApp,
          idProfile: this.settingsProfileId
        }
      ]
    };

    const now = Math.floor(Date.now() / 1000);
    const expiry = now + Math.floor(this.expiryHours * 60 * 60);

    const token = await new SignJWT({
      rights,
      cty: 'JSON',
      timeBefore: now
    })
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'JWT'
      })
      .setIssuer(this.issuer)
      .setSubject(this.subject)
      .setIssuedAt(now)
      .setExpirationTime(expiry)
      .sign(privateKey);

    return `Bearer ${token}`;
  }
}

/*
Example:

import { JwtTokenGenerator } from './JwtTokenGenerator';

const bearer = await JwtTokenGenerator.createBearer(12345);

const response = await request.get('/your-api', {
  headers: {
    Authorization: bearer
  }
});
*/
