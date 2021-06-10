package smsloader;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class RomHeader {

	private byte[] bytes;

	public RomHeader(Program program) throws MemoryAccessException, AddressOutOfBoundsException, IllegalArgumentException {
		byte[] bytes = new byte[5];
		program.getMemory().getBytes(
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x7ffa),
			bytes
		);

		setBytes(bytes);
	}

	public RomHeader(byte[] bytes) throws IllegalArgumentException {
		setBytes(bytes);
	}

	private void setBytes(byte[] bytes) throws IllegalArgumentException {
		if (bytes.length != 5) {
			throw new IllegalArgumentException("bytes wrong size");
		}
		this.bytes = Arrays.copyOf(bytes, 5);
	}

	public int checksum() {
		return bytes[0] & 0xff | ((bytes[1] & 0xff) << 8);
	}

	public int productCode() {
		return bytes[2] & 0xff | ((bytes[3] << 8) & 0xff00);
	}

	public int version() {
		return bytes[4] & 0xff;
	}

	public String toString() {
		return String.format("ROM Header\r\nChecksum 0x%h\r\nProduct Code 0x%h\r\nVersion 0x%h", this.checksum(),
				this.productCode(), this.version());
	}

	public static RomHeader findHeader(ByteProvider provider) throws IOException {
		// Validate this is a proper SMS/GG file by looking for the header

		// The 16-byte SMS/GG header can be found at one these offsets within the file
		long headerOffsets[] = { 0x1ff0, 0x3ff0, 0x7ff0 };
		long sizeOfHeader = 16;
		String signature = "TMR SEGA";

		for (int i = 0; i < headerOffsets.length; i++) {

			if (provider.length() < headerOffsets[i] + sizeOfHeader) {
				break;
			}

			// the first 8 bytes of header are a signature
			byte sig[] = provider.readBytes(headerOffsets[i], 8);
			if (Arrays.equals(sig, signature.getBytes())) {
				// found the SMS/GG header, this is a valid format
				return new RomHeader(provider.readBytes(headerOffsets[i] + 8 + 2, 5));
			}
		}
		return null;
	}
}
