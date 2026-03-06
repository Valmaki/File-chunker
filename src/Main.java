/*
Copyright (C) 2026 Valmaki

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You must keep this notice intact in any redistributed or modified version.
*/

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZInputStream;
import org.tukaani.xz.XZOutputStream;

import me.keys.KeyPackage;

/*
*Optimalisations:
*	-Buffer size 4 KB -> 1 MB 2/2 ✓
*	-Instant in memory, no temp file 0/2
*	-Multi thread 0/2
*/

public class Main {
	private static final long GCM_MAX = 64L << 30; //64 GB
	private static final int BUFF_SIZE = 1 << 20; //1 MB

	private static final Scanner scanner = new Scanner(System.in, "UTF-8");
	private static final SecureRandom rand = new SecureRandom();

	public static void main(String[] args) throws Exception {
		if (args.length >= 1 && args[0].toLowerCase().equals("console")) { //Console mode
			if (getBoolean("Set mode (fragmenting/defragmenting)! ", "fragmenting", "defragmenting")) { //Fragmenting
				System.out.print("Path to the full file: ");
				String fullPath = scanner.nextLine();
				long chunkSize = getSize() - 8;
				byte ops = 0;
				SecretKey key = null;
				byte[] salt = null;
				if (getBoolean("Do you want to encrypt the file (yes/no)? ", "yes", "no")) {
					if (getBoolean("Which encryption type (password based/key based)? ", "password based", "key based")) {
						ops = 0b00000011; //xxxxxx11 == password based encrypted
						salt = new byte[32];
						rand.nextBytes(salt);
						System.out.print("Password: ");
						char[] pw = scanner.nextLine().toCharArray();
						PBEKeySpec spec = new PBEKeySpec(pw, salt, 300_000, 256);
						SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
						byte[] hash = skf.generateSecret(spec).getEncoded();
						for (int i = 0; i < pw.length; i++) pw[i] = 0;
						key = new SecretKeySpec(hash, "AES");
						for (int i = 0; i < 32; i++) hash[i] = 0;
					} else {
						ops = 0b00000010; //xxxxxx10 == key based encrypted
						System.out.print("Parh to keys file: ");
						key = new KeyPackage(new File(scanner.nextLine())).getSecretKey();
						if (key == null) throw new Exception("The key file doesn't contains secret key!");
					}
				}
				int preset = getIntInRange("Compressing level (0-9): ", 0, 9);
				LZMA2Options options = new LZMA2Options();
				options.setPreset(preset);
				File xzFile = new File(fullPath + ".xz.temp");
				xzFile.createNewFile();
				xzFile.deleteOnExit();
				byte[] hash;
				//Compressing
				byte[] buffer = new byte[BUFF_SIZE];
				try (FileOutputStream fos = new FileOutputStream(xzFile, false);
						XZOutputStream out = new XZOutputStream(fos, options);
						FileInputStream fis = new FileInputStream(fullPath)) {
					int read;
					MessageDigest d = MessageDigest.getInstance("SHA256");
					if (key == null) {
						while ((read = fis.read(buffer)) != -1) {
							out.write(buffer, 0, read);
							d.update(buffer, 0, read);
						}
					} else {
						if (salt != null) out.write(salt);
						byte[] iv = new byte[12];
						rand.nextBytes(iv);
						out.write(iv);
						while (true) {
							long c = GCM_MAX;
							Cipher encoder = Cipher.getInstance("AES/GCM/NoPadding");
							GCMParameterSpec gcmspec = new GCMParameterSpec(128, iv);
							encoder.init(Cipher.ENCRYPT_MODE, key, gcmspec);
							while (((read = fis.read(buffer, 0, (int) Math.min(BUFF_SIZE, c - BUFF_SIZE))) != -1)) {
								out.write(encoder.update(buffer, 0, read));
								d.update(buffer, 0, read);
								c -= read;
								if (c <= 0) break; //New iv required
							}
							out.write(encoder.doFinal());
							if (c > 0) break;
							inc(iv);
						}
					}
					hash = d.digest();
				}
				//Make the full file (headler + compressed file)
				File temp = new File(fullPath + ".fullSplit.temp");
				temp.createNewFile();
				temp.deleteOnExit();
				long total = xzFile.length() + 41;
				long chunks = (total + chunkSize - 1) / chunkSize;
				System.out.println("Prepare to make the " + chunks + ((chunks == 1) ? " chunk." : " chunks."));
				try (FileInputStream fis = new FileInputStream(xzFile);
						FileOutputStream fos = new FileOutputStream(temp, false)) {
					fos.write(ops);
					fos.write(writeLong(chunks));
					fos.write(hash);
					int read;
					while ((read = fis.read(buffer)) != -1) {
						fos.write(buffer, 0, read);
					}
				}
				//Splitting
				xzFile.delete();
				if (chunkSize < BUFF_SIZE) buffer = new byte[(int) chunkSize];
				String base = fullPath + ".split_";
				try (FileInputStream fis = new FileInputStream(temp)) {
					long last = System.currentTimeMillis();
					for (long i = 0; i < chunks; i++) {
						long different = System.currentTimeMillis() - last;
						last = System.currentTimeMillis();
						System.out.print("\r" + i + "/" + chunks + " " + (i == 0 ? 0 : (i * 100) / chunks) + "% " + (i == 0 ? 0 : (different * (chunks - i))) + " ms left.");
						String path = base + i;
						try (FileOutputStream fos = new FileOutputStream(path, false)) {
							fos.write(writeLong(i));
							long remaining = chunkSize;
							int read;
							while ((read = fis.read(buffer, 0, (int) Math.min(remaining, buffer.length))) > 0) {
								fos.write(buffer, 0, read);
								remaining -= read;
							}
						}
					}
				}
				temp.delete();
				
				System.out.println("\nFragmenting complete.\nFragments:");
				for (long i = 0; i < chunks; i++) {
					System.out.println('"' + base + i + '"');
				}
				System.out.println("\n\n");
			} else { //Defragmenting
				System.out.print("Path to the first file: ");
				String path = scanner.nextLine();
				if (!path.endsWith(".split_0")) {
					System.err.println("Illegal file format!");
					return;
				}
				byte ops;
				long chunks;
				byte[] hash = new byte[32];
				//Fragments to file
				byte[] buffer = new byte[BUFF_SIZE];
				File fullFile = new File(path.substring(0, path.length() - 8) + ".fullSplit.temp");
				fullFile.createNewFile();
				fullFile.deleteOnExit();
				try (FileOutputStream fos = new FileOutputStream(fullFile, false)) {
					try (FileInputStream fis = new FileInputStream(path)) {
						if (readLong(fis) != 0) throw new Exception("Invalid file!");
						int read = fis.read();
						if (read == -1) throw new Exception("Invalid file");
						ops = (byte) (read & 0xFF);
						chunks  = readLong(fis);
						readFully(hash, fis);
						while ((read = fis.read(buffer)) != -1) {
							fos.write(buffer, 0, read);
						}
					}
					String base = path.substring(0, path.length() - 1);
					long last = System.currentTimeMillis();
					for (long i = 1; i < chunks; i++) {
						String current = base + i;
						long different = System.currentTimeMillis() - last;
						last = System.currentTimeMillis();
						System.out.print("\r" + i + "/" + chunks + " " + (i == 0 ? 0 : (i * 100) / chunks) + "% " + (i == 0 ? 0 : (different * (chunks - i))) + " ms left.");
						try (FileInputStream fis = new FileInputStream(current)) {
							if (readLong(fis) != i) {
								fos.close();
								fullFile.delete();
								throw new IOException("Corrupted chunks!");
							}
							int read;
							while ((read = fis.read(buffer)) != -1) {
								fos.write(buffer, 0, read);
							}
						}
					}
				}
				//Decompressing
				System.out.println("\nDecompressing...");
				MessageDigest d = MessageDigest.getInstance("SHA256");
				try (FileInputStream fis = new FileInputStream(fullFile);
						XZInputStream in = new XZInputStream(fis);
						FileOutputStream fos = new FileOutputStream(path.substring(0, path.length() - 8))) {
					if (ops == 0) { //Not encoded
						int read;
						while ((read = in.read(buffer)) != -1) {
							d.update(buffer, 0, read);
							fos.write(buffer, 0, read);
						}
					} else { //Encoded
						System.out.println("The file is encrypted.");
						SecretKey key;
						if (ops == 0b00000011) { //Password based
							byte[] salt = new byte[32];
							readFully(salt, in);
							System.out.print("Password: ");
							char[] pw = scanner.nextLine().toCharArray();
							PBEKeySpec spec = new PBEKeySpec(pw, salt, 300_000, 256);
							SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
							byte[] h = skf.generateSecret(spec).getEncoded();
							for (int i = 0; i < pw.length; i++) pw[i] = 0;
							key = new SecretKeySpec(h, "AES");
							for (int i = 0; i < 32; i++) h[i] = 0;
						} else if (ops == 0b00000010) { //Key based
							System.out.print("Parh to keys file: ");
							key = new KeyPackage(new File(scanner.nextLine())).getSecretKey();
							if (key == null) throw new Exception("The key file doesn't contains secret key!");
						} else {
							System.err.println("Unknown options!");
							new File(path.substring(0, path.length() - 8)).delete();
							return;
						}
						byte[] iv = new byte[12];
						byte[] tag = new byte[16];
						readFully(iv, in);
						while (true) {
							long c = GCM_MAX;
							Cipher decoder = Cipher.getInstance("AES/GCM/NoPadding");
							GCMParameterSpec gcmspec = new GCMParameterSpec(128, iv);
							decoder.init(Cipher.DECRYPT_MODE, key, gcmspec);
							int read;
							while ((read = in.read(buffer, 0, (int) Math.min(BUFF_SIZE, c - BUFF_SIZE))) != -1) {
								byte[] paytext = decoder.update(buffer, 0, read);
								fos.write(paytext);
								d.update(paytext);
								c -= read;
								if (c <= 0) break; //New iv required
							}
							byte[] paytext = decoder.doFinal(readFullyOrRet(in, tag));
							fos.write(paytext);
							d.update(paytext);
							if (c > 0) break;
							inc(iv);
						}
					}
				}
				if (!Arrays.equals(d.digest(), hash)) {
					System.err.println("Integrity error!");
					new File(path.substring(0, path.length() - 8)).delete();
					return;
				}
				System.out.println("Defragmenting is completed.");
			}
			


		} else { //GUI mode
			throw new Exception("GUI mod not available!\nUse \"console\" as the first argument!");
		}
	}

	private static boolean getBoolean(String msg, String t, String f) {
		while (true) {
			System.out.print(msg);
			String result = scanner.nextLine().toLowerCase();
			if (result.equals(t)) return true;
			if (result.equals(f)) return false;
			System.err.println("Invalid answer!");
		}
	}
	private static int getIntInRange(String msg, int min, int max) {
		if (min > max) throw new IllegalArgumentException("Minimum value can't be bigger than maximum value!");
		while (true) {
			System.out.print(msg);
			int result = scanner.nextInt();
			scanner.nextLine();
			if (result >= min && result <= max) return result;
			System.err.println("Out of range!");
		}
	}
	private static long getSize() {
		while (true) {
			System.out.print("Maximum chunk size: ");
			String[] args = scanner.nextLine().toLowerCase().split("\\ ");
			if (args.length == 1) {
				long val = Long.parseLong(args[0]);
				if (val < 1024) {
					System.err.println("The maximum size can't be lower than 1024 B!");
					continue;
				}
				return val;
			}
			String last = args[args.length - 1];
			StringBuilder sb = new StringBuilder(args[0]);
			for (int i = 1; i < (args.length - 1); i++) sb.append(args[i]);
			long val = Long.parseLong(sb.toString());
			if (last.equals("b")) {
				if (val < 1024) {
					System.err.println("The maximum size can't be lower than 1024 B!");
					continue;
				}
				return val;
			}
			if (val < 1) {
				System.err.println("Illegal size!");
				continue;
			}
			if (last.equals("kb")) return val << 10;
			if (last.equals("mb")) return val << 20;
			if (last.equals("gb")) return val << 30;
			if (last.equals("tb")) return val << 40;
			return Long.parseLong(sb.append(last).toString());
		}
	}


	private static void inc(byte[] arr) {
		for (int i = arr.length - 1; i >= 0; i--) {
			arr[i]++;
			if (arr[i] != 0) return;
		}
	}

	private static byte[] writeLong(long val) {
		byte[] r = new byte[8];
		for (int i = 0; i < 8; i++) r[i] = (byte) ((val >>> (56 - (i * 8))) & 0xFF);
		return r;
	}
	private static long readLong(InputStream in) throws IOException {
		byte[] b = new byte[8];
		readFully(b, in);
		long r = 0;
		for (int i = 0; i < 8; i++) r |= ((long) (b[i] & 0xFF)) << (56 - (i * 8));
		return r;
	}
	private static byte[] readFullyOrRet(InputStream in, byte[] arr) throws IOException {
		int off = 0;
		int read;
		while ((read = in.read(arr, off, arr.length - off)) > 0) {
			off += read;
			if (off == arr.length) return arr;
		}
		if (off == 0) return new byte[0];
		byte[] r = new byte[off];
		System.arraycopy(arr, 0, r, 0, off);
		return r;
	}
	private static void readFully(byte[] arr, InputStream in) throws IOException {
		int read = 0;
		while (read < arr.length) {
			int c = in.read(arr, read, arr.length - read);
			if (c == -1) throw new IOException("EOF");
			read += c;
		}
	}
}