import fs from 'fs';
import path from 'path';
import { importPKCS8, SignJWT } from 'jose';

export class JwtTokenGenerator {
  private static readonly SETTINGS_PROFILE_ID = 4; // Replace with actual SETTINGS profile ID
  private static readonly ISSUER = 'f49426';
  private static readonly SUBJECT = 'f49426';
  private static readonly EXPIRY_HOURS = 8;

  private static readonly PRIVATE_KEY_PATH = path.resolve(
    process.cwd(), 'certificates', 'jwt-private-key.pem'
  );

  public static async createBearer(idApp: number): Promise<string> {
    if (!Number.isInteger(idApp) || idApp <= 0) {
      throw new Error('Application ID must be a positive integer');
    }

    if (!fs.existsSync(this.PRIVATE_KEY_PATH)) {
      throw new Error(`JWT private key not found: ${this.PRIVATE_KEY_PATH}`);
    }

    const pem = fs.readFileSync(this.PRIVATE_KEY_PATH, 'utf8');
    const privateKey = await importPKCS8(pem, 'RS256');

    const rights = {
      appProfilePairs: [{
        idApp,
        idProfile: this.SETTINGS_PROFILE_ID
      }]
    };

    const now = Math.floor(Date.now() / 1000);

    const token = await new SignJWT({
      rights,
      cty: 'JSON',
      timeBefore: now
    })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .setIssuer(this.ISSUER)
      .setSubject(this.SUBJECT)
      .setIssuedAt(now)
      .setExpirationTime(now + this.EXPIRY_HOURS * 60 * 60)
      .sign(privateKey);

    return `Bearer ${token}`;
  }
}
