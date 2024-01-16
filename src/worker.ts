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

import { AwsClient } from 'aws4fetch';


export interface Env {
	//We assume that cloudflares encrypted env vars are secure
	KEY: string; // {"kty":"oct","key_ops":["encrypt","decrypt"],"alg":"A256GCM","ext":true,"k":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"}
	encrypted: KVNamespace;
}

export interface EncryptedRoute {
	data: string;
	iv: string;
}

export interface Route {
	host: string;
	region: string;
	service: string;
	frontId: string;
	frontSecret: string;
	backId: string;
	backSecret: string;

}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const yeet: Response = new Response('<?xml version="1.0" encoding="UTF-8"?><Error><Code>InvalidArgument</Code><Message>Invalid Argument: Authorization</Message></Error>', { headers: { "Content-Type": "application/xml" }, status: 400 });
		console.log("IP       :",request.headers.get('CF-Connecting-IP'));
		console.log("URL      :",request.url.toString());
		console.log("AGENT    :",request.headers.get('User-Agent'));
		try {
			const auth: string = request.headers.get("Authorization") || "";
			if(auth.length == 0 || !auth.startsWith("AWS4-HMAC-SHA256 Credential=")) {
				console.log("AUTHFORM : Bad");
				return yeet;
			}
	
			console.log("AUTHFORM : Good");
			const access: string = auth.replace("AWS4-HMAC-SHA256 Credential=","").split('/')[0];
			const specialChars: RegExp = /[`!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/;
			console.log("ID       :", access);
			if (specialChars.test(access) && access.length >= 64 && access.length <= 128) {
				console.log("AUTH     : Dirty");
				return yeet;
			}
			console.log("AUTH     : Clean");
	
			const signedHeadersMatch = /SignedHeaders=([a-zA-Z0-9;-]+)/.exec(auth);
			if (!signedHeadersMatch || !signedHeadersMatch[1]) {
				return yeet;
			}
			const signedHeaders = signedHeadersMatch[1].split(';');
			const verifyHeaders: Record<string, string> = {};
			for (const header of signedHeaders) {
				const value = request.headers.get(header);
				if (value) {
				  verifyHeaders[header] = value;
				}
			}
			console.log("HEADERS  :",JSON.stringify(verifyHeaders));
	
			const route: Route | null = await getRoute(access, env);
			if (route == null) {
				return yeet;
			}
			const frontend: AwsClient = new AwsClient({
				"accessKeyId": route.frontId,
				"secretAccessKey": route.frontSecret,
				"region": route.region,
				"service": route.service
			});
	
			const verifyRequest = await frontend.sign(request, {
				headers: verifyHeaders,
				aws: {
				  datetime: request.headers.get("x-amz-date") || "",
				  allHeaders: true,
				},
			});
			
			//We have to do this as some s3 implementations add random spaces
			const verifyAuth: string = (verifyRequest.headers.get("Authorization") || "").replace(/, /g, ',');
			const requestAuth: string = (request.headers.get("Authorization") || "").replace(/, /g, ',');

			console.log("REQUEST  :",requestAuth);
			console.log("RESIGN   :",verifyAuth);
	
			if (verifyAuth.valueOf() !== requestAuth.valueOf()) {
				console.log("VERIFY   : Failed");
				return yeet;
			}
			console.log("VERIFY   : Passed");
	
			const backend: AwsClient = new AwsClient({
				"accessKeyId": route.backId,
				"secretAccessKey": route.backSecret,
				"region": route.region,
				"service": route.service,
				initRetryMs: 10,
			});

			var url: URL = new URL(request.url);
			url.hostname = route.host;
			var newRequest: Request = new Request(request, { headers: verifyHeaders});
			newRequest.headers.set("host", route.host);
			console.log("BACKEND  :", route.host);

			var response: Response;
			if (request.method === "GET") {
				response = await backend.fetch(url, {method: newRequest.method});
			} else {
				response = await backend.fetch(url, {body: newRequest.body, method: newRequest.method});
			}
			console.log("STATUS   :", response.status);
			return response;

		} catch (error){
			console.log("EXCEPT   :", error);
			return yeet;
		}
	},
};

//helpers
async function getRoute(access: string, env: Env): Promise<Route|null> {
	const encryptedData = await env.encrypted.get<EncryptedRoute>(access, "json");
	if (encryptedData === null) {
		return null; 
	}
	return await decrypt(encryptedData, env.KEY);
}


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

async function decrypt(encryptedData: EncryptedRoute, keyString: string): Promise<Route> {
	const key: CryptoKey = await importKey(keyString);
	const decodedIV: ArrayBufferLike = strToArrayBuff(encryptedData.iv);
	const decodedEncryptedData: ArrayBufferLike = strToArrayBuff(encryptedData.data);
	const decryptedData = await crypto.subtle.decrypt(
		{
		name: 'AES-GCM',
		iv: decodedIV,
		},
		key,
		decodedEncryptedData
	);

	const decoder: TextDecoder = new TextDecoder();
	const data: Route = JSON.parse(decoder.decode(decryptedData));
	return data;
}

function strToArrayBuff(base64: string): ArrayBufferLike {
	var binaryString: string = atob(base64);
	var bytes: Uint8Array = new Uint8Array(binaryString.length);
	for (var i = 0; i < binaryString.length; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes.buffer;
}

async function exportKey(key: CryptoKey): Promise<string> {
	const keyData: ArrayBuffer | JsonWebKey = await crypto.subtle.exportKey('jwk', key);
	return JSON.stringify(keyData);
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
  
	return { encryptedData: encryptedDataString, iv: ivString };
}

function arrayBuffToStr(buffer: ArrayBufferLike): string {
	const uint8Array: Uint8Array = new Uint8Array(buffer);
	const numberArray: number[] = Array.from(uint8Array);
	const base64String: string = btoa(String.fromCharCode.apply(null, numberArray));
	return base64String;
}