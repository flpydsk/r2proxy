/*
    Copyright (C) 2023-2024 FloppyDisk
    https://github.com/flpydsk/r2proxy.git

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 only.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/* 
yeah yeah do it urself
curl -X POST http://127.0.0.1:8787 -H "Content-Type: application/json" -H "X-Auth-Key: $(cat ./key)" -d "$(cat ./data.txt)"
data.txt = { "host": "", "region": "auto", "service":"s3", "frontId":"", "frontSecret":"", "backId": "", "backSecret": "" }
*/



export interface Env {
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if(request.method === "POST") {
			return new Response(JSON.stringify(await encrypt(JSON.stringify(await request.json()), await importKey(request.headers.get("X-Auth-Key") || ""))));
		}
		return new Response('{}');
	},
};


async function importKey(keyString: string): Promise<CryptoKey> {
	const keyData: ArrayBuffer = JSON.parse(keyString);
	const key: CryptoKey = await crypto.subtle.importKey(
	'jwk',
	keyData,
	{ name: 'AES-GCM' },
	true,
	['encrypt', 'decrypt']
	);
	return key;
}

async function encrypt(text: string, key: CryptoKey) {
	const encoder = new TextEncoder();
	const data = encoder.encode(text);
	const iv = crypto.getRandomValues(new Uint8Array(12)); // 96 bits IV
	const encryptedData = await crypto.subtle.encrypt(
	  {
		name: 'AES-GCM',
		iv,
	  },
	  key,
	  data
	);

	const encryptedDataString = arrayBuffToStr(encryptedData);
	const ivString = arrayBuffToStr(iv);

	return { data: encryptedDataString, iv: ivString };
  }

function arrayBuffToStr(buffer: ArrayBufferLike): string {
	const uint8Array: Uint8Array = new Uint8Array(buffer);
	const numberArray: number[] = Array.from(uint8Array);
	const base64String: string = btoa(String.fromCharCode.apply(null, numberArray));
	return base64String;
}