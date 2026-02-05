import * as fs from 'node:fs/promises';
import { TrustList } from '../../src/cose';

export const DefaultTrustListPath = 'tests/fixtures/trust-list.pem';

export async function setTrustList(trustListFile: string = DefaultTrustListPath): Promise<void> {
    const trustListData = (await fs.readFile(trustListFile)).toString();
    TrustList.setTrustAnchors([trustListData]);
}
