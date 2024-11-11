package com.sahamati.rahasya.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sahamati.rahasya.service.ECCService;

@RestController
@RequestMapping("/api/ecc")
public class ECCController {

	@Autowired
	private ECCService eccService;

	@GetMapping("/keypair")
	public ResponseEntity<Map<String, String>> generateKeyPair() {
		return ResponseEntity.ok(eccService.generateKeyPair());
	}

	@PostMapping("/sharedkey")
	public ResponseEntity<String> generateSharedKey(@RequestBody Map<String, String> request) {
		String sharedKey = eccService.generateSharedKey(request.get("remotePublicKey"), request.get("ourPrivateKey"));
		return ResponseEntity.ok(sharedKey);
	}

	@PostMapping("/encrypt")
	public ResponseEntity<String> encryptData(@RequestBody Map<String, String> request) {
		String encryptedData = eccService.encryptData(request.get("remoteKeyMaterial"), request.get("ourPrivateKey"),
				request.get("base64RemoteNonce"), request.get("base64YourNonce"), request.get("data"));
		return ResponseEntity.ok(encryptedData);
	}

	@PostMapping("/decrypt")
	public ResponseEntity<String> decryptData(@RequestBody Map<String, String> request) {
		String decryptedData = eccService.decryptData(request.get("remoteKeyMaterial"), request.get("ourPrivateKey"),
				request.get("base64RemoteNonce"), request.get("base64YourNonce"), request.get("base64Data"));
		return ResponseEntity.ok(decryptedData);
	}
}
