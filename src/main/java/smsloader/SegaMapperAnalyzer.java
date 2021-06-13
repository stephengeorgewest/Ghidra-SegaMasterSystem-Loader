package smsloader;

import java.util.List;

import ghidra.app.plugin.processors.generic.Operand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import smsloader.rom.PhantasyStar;

public class SegaMapperAnalyzer extends AbstractAnalyzer {

	private static MapperOptions MAPPER_DEFAULT_OPTION = MapperOptions.SegaMapper;
	private MapperOptions mapper = MAPPER_DEFAULT_OPTION;
	private static final String OPTION_MAPPER = "Mapper";

	private Boolean apply_rom_data = false;
	private Boolean ignore_checksum = false;
	private Boolean ignore_version = false;
	private int override_product_version = -1;

	public static enum MapperOptions {
		SegaMapper(1),Codemasters(2),Korean(3),MSX_Nemesis(4),Janggun(5);
		private int mapperOption;

		MapperOptions(int mapperOption){
			this.mapperOption = mapperOption;
		}
		public int getMapperOption() {
			return this.mapperOption;
		}
	}

	public SegaMapperAnalyzer() {
		super("The Sega mapper", "https://www.smspower.org/Development/Mappers", AnalyzerType.INSTRUCTION_ANALYZER);
		super.setPriority(AnalysisPriority.DISASSEMBLY);
		// https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/ConstantPropagationAnalyzer.java
		// ?
		// AnalysisPriority.REFERENCE_ANALYSIS.before().before().before().before()
		// <del>which is DISASSEMBLY.before() ?or </del> is it 500 - 4 = 496?
		/*
		 * AnalysisPriority DISASSEMBLY
		 *
		 * Defines disassembly as the third priority for automatic analysis. Disassembly
		 * of code found through good solid flow will occur at this priority. More
		 * heuristic code recovery will occur later.
		 */

		/*
		 * AnalysisPriority.CODE_ANALYSIS
		 * 
		 * Defines code analysis as the fourth priority for automatic analysis. If your
		 * analyzer is looking at RAW CODE, you should general go at or after this
		 * priority. Usually this is used in conjunction with analyzers that process new
		 * instructions AnalyzerType.INSTRUCTIONS. It is also useful for those analyzers
		 * that depend on code, but want to analyze flow, such as non-returning
		 * functions, that should happen before functions are widely laid down. If bad
		 * flow is not fixed at an early priority, switch stmt recovery, function
		 * boundaries, etc... may need to be redone and bad stuff cleaned up.
		 */
	}

	@Override
	public boolean added(Program program, AddressSetView addressSetView, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		monitor.checkCanceled();

		// TODO: loop through all addresses eg
		// [[ram:07da, ram:0806] [ram:0847, ram:086e] ]
		// [[ram:00af, ram:00bd] [ram:00e6, ram:00f0] ]
		// [[ram:035a, ram:0376] [ram:03cd, ram:03f9] [ram:074d, ram:07b9] [ram:6b62,
		// ram:6b8d] [ram:7b05, ram:7b17] ]
		for (AddressRange ar : addressSetView) {
			Instruction inst = program.getListing().getInstructionAt(ar.getMinAddress());
			Address add = inst.getAddress();
			while (inst != null && add.subtract(ar.getMinAddress()) >= 0 && ar.getMaxAddress().subtract(add) >= 0) {
				
				if(this.apply_rom_data) {
					PhantasyStar.added(
						program, add, monitor, log,
						ignore_checksum, ignore_version, override_product_version
					);
				}

				String add_str = add.toString(false);
				int add_int = Integer.parseInt(add_str, 16);
				// if not a call, or has no fallthru
				/* if (/*inst.getFlowType().isCall() || inst.getFlowType().isFlow()) { */
				FlowType flowtype = inst.getFlowType();

				int targetAddress = -1;
				if (flowtype.isJump() && flowtype.isUnConditional()) {
					//
					// **************************************************************
					// * FUNCTION *
					// **************************************************************
					// * undefined CallSndInit()
					// * undefined A:1 <RETURN> CallSndInit XREF[1]: ram:00a2(c)
					//
					// ram:02ed 21 ff ff LD HL,0xffff
					// ram:02f0 36 0c LD (HL=>BankSelect[2]),0xc ;bank_12
					// ram:02f2 c3 00 80 JP DialogueBlock ; should be bank_12_0x8000
					//
					int op_type = inst.getOperandType(0);
					if ((op_type & OperandType.ADDRESS) != 0) {
						Object op0 = inst.getOpObjects(0)[0];
						Address op0_address = (Address) op0;
						String address_string = op0_address.toString(false);
						targetAddress = Integer.parseInt(address_string, 16);
						// String op_string = inst.getDefaultOperandRepresentation(0);
						// targetAddress = Integer.parseInt(op_string.replace("0x", ""), 16);
					}
				}

				// **************************************************************
				// * SUBROUTINE *
				// **************************************************************
				// ShowDialogue_B12
				// XREF[7]: ram:067c(c), ram:0687(c), ram:0697(c), ram:06c8(c),
				// ram:06d3(c), ram:06e7(c), ram:06f2(c)
				// ram:31cf 3e 0c LD A,0xc
				// ram:31d1 32 ff ff LD (BankSelect[2]),A
				// ram:31d4 3a d3 c2 LD A,(DAT_ram_c2d3) = ??
				//
				
				if (inst.getMnemonicString().equals("LD")) {
					int i = inst.getInputObjects().length;
					if(i == 1) {
						int op_type = inst.getOperandType(1);
						if(OperandType.isAddress(op_type)) {
							Object op1 = inst.getOpObjects(1)[0];
							targetAddress = getAddressString(op1);
						}
					}
				}
				
				
				// ram:065f 21 ff ff        LD         HL,0xffff
				// ram:0662 36 10           LD         (HL),0x10 ; 16
				// ram:0664 21 d8 ba        LD         HL,0xbad8
				// ram:0667 11 00 58        LD         DE,0x5800
				// ram:066a cd fa 03        CALL       FUN_ram_03fa                                     undefined FUN_ram_03fa()
				//  -->...
				//         ram:03fe cd 07 04        CALL       FUN_ram_0407                                     undefined FUN_ram_0407()
				// -->
				//                 **************************************************************
				//                 *                          FUNCTION                          *
				//                 **************************************************************
				//                 undefined FUN_ram_0407()
				// undefined         A:1            <RETURN>
				//                 FUN_ram_0407                                    XREF[1]:     ram:03fe(c)  
			// ram:0407 7e              LD         A,(HL) ; LD A,(HL=>DAT_bank_16__bad8)
				// ram:0408 23              INC        HL
				// ram:0409 b7              OR         A
				// ram:040a c8              RET        Z
				// ram:040b 4f              LD         C,A
				// ram:040c e6 7f           AND        0x7f

				int bank_num = -1;
				int bank_select_address = -1;
				/* if address is in (0x03ff,0xc000] point to bank listed in register 0xfff(def) */
				if (0x03ff <= targetAddress && targetAddress < 0x4000) {
					bank_select_address = 0xfffd;
				} else if (0x4000 <= targetAddress && targetAddress < 0x8000) {
					bank_select_address = 0xfffd;
				} else if (0x8000 <= targetAddress && targetAddress < 0xc000) {
					/* if address is in 0x8000-0xc000 point to bank listed in register 0xffff */
					bank_select_address = 0xffff;
				}

				if (bank_select_address > 0) {
					// TODO: look higher, but not past minAddress or address range[0]
					Address min_address = addressSetView.getMinAddress();
					Address min_addres_in_range = ar.getMinAddress();
					Instruction previous = inst.getPrevious();
					// walk the program backwards looking for writes to 0xfff
					// get the instruction there
					// example writing defaults for each
					//
					// MainSetup XREF[1]: ram:0006(j)
					//
					// ram:0084 f3 DI ram:0085 31 00 cb LD SP,0xcb00
					// ram:0088 21 fc ff LD HL,0xfffc
					// ram:008b 36 80 LD (HL),0x80
					// ram:008d 23 INC HL ; 0xfffd
					// ram:008e 36 00 LD (HL),0x0
					// ram:0090 23 INC HL ; 0xfffe
					// ram:0091 36 01 LD (HL),0x1
					// ram:0093 23 INC HL ; 0xffff
					// ram:0094 36 02 LD (HL),0x2
					//

					/** write value to ram if writing to 0xfffc-0xffff */
					InstructionContext context = inst.getInstructionContext();
					String mnemonic = previous.getMnemonicString();
					int opNum = previous.getNumOperands();
					if (mnemonic.equals("LD") && opNum == 2) {
						// ram:0088 21 fc ff LD HL,0xfffc
						// has 1 input 1 result
						// ram:008b 36 80 LD (HL),0x80
						// has 2 input 0 result
						Object[] input = previous.getInputObjects();
						if (input.length == 2) {

							int op0_type = previous.getOperandType(0);
							String op0_r = previous.getDefaultOperandRepresentation(0);
							if (OperandType.isRegister(op0_type) && op0_r.equals("HL")) {

								int op1_type = previous.getOperandType(1);
								// String op1_r = previous.getDefaultOperandRepresentation(1);
								if (op1_type == OperandType.SCALAR/* && op1_r.equals("text") */) {
									Object op0 = previous.getOpObjects(1)[0];
									Scalar op0_scalar = (Scalar) op0;
									int possible_bank_num = (int) op0_scalar.getUnsignedValue();

									Instruction p_hl = previous.getPrevious();
									String p_mnemonic = p_hl.getMnemonicString();
									int p_opNum = p_hl.getNumOperands();
									if (p_mnemonic.equals("LD") && p_opNum == 2) {

										Object[] result = p_hl.getResultObjects();
										if (result.length == 1) {
											int op0_result_type = p_hl.getOperandType(0);
											String op0_result_r = previous.getDefaultOperandRepresentation(0);
											if (OperandType.isRegister(op0_result_type) && op0_result_r.equals("HL")) {
												Object[] input_hl = p_hl.getInputObjects();
												if (input_hl.length == 1) {
													if (OperandType.isScalar(p_hl.getOperandType(1))) {
														Scalar p_hl_scalar = (Scalar) p_hl.getOpObjects(1)[0];
														if (p_hl_scalar.getUnsignedValue() == bank_select_address) {
															bank_num = possible_bank_num;
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

				/* Add reference to bank */
				if (bank_num > -1 && bank_num < 32) {

					/*
					 * ReferenceManager refman = program.getReferenceManager(); int count =
					 * refman.getReferenceCountFrom(inst.getAddress()); Reference r =
					 * refman.addExternalReference(inst.getAddress(), extNamespace, extLabel,
					 * extAddr, source, opIndex, type) if(count == 0) { refman.setPrimary(r, true);
					 * }
					 */
					AddressSpace space = program.getAddressFactory()
							.getAddressSpace(String.format("bank_%02d", bank_num));
					Address a = space.getAddress(targetAddress);
					inst.removeOperandReference(bank_num, a);
					Reference r = inst.getPrimaryReference(0);
					if (r != null) {
						// inst.setPrimaryMemoryReference(r);
						Address aa = r.getToAddress();
						inst.removeOperandReference(0, aa);
					} /* else { */
					inst.addOperandReference(0, a, RefType.UNCONDITIONAL_JUMP, SourceType.DEFAULT);
					// clear flow and repair?
					/* } */
					// inst.addOperandReference(0, null, null, null)
				}
				inst = inst.getNext();
				if(inst != null) {
					add = inst.getAddress();
				}
			}
		}
		if(this.apply_rom_data) {
			return PhantasyStar.added(
				program, addressSetView, monitor, log,
				ignore_checksum, ignore_version, override_product_version
			);
		}
		return true;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		List<Symbol> h = program.getSymbolTable().getLabelOrFunctionSymbols("Header", null);
		DataType d = program.getDataTypeManager().getDataType("RomHeader");
		for (Symbol ss : h) {
			Address address = ss.getAddress();
			byte[] b = new byte[16];
			try {
				program.getMemory().getBytes(address, b);
				// ghidra.program.model.mem.ByteMemoryBufferImpl(address, b, false);
			} catch (MemoryAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		// String s = d.getRepresentation(null, null, 16);
		if (h != null && d != null)
			return true;

		return super.getDefaultEnablement(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// TODO Auto-generated method stub
		return super.canAnalyze(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// HelpLocation h = new HelpLocation(description,
		// description);"https://www.smspower.org/Development/Mappers"
		// TODO: switch to dropdown to choose between mappers
		options.registerOption(OPTION_MAPPER, MAPPER_DEFAULT_OPTION, null, "Sega Mapper");

		options.registerOption(Constants.OPTION_APPLY_ROM_DATA, true, null, "");
		options.registerOption(Constants.OPTION_IGNORE_CHECKSUM, false, null, "");
		options.registerOption(Constants.OPTION_IGNORE_VERSION, false, null, "");
		
		String product_code_string = "0";
		try{
			RomHeader romHeader = new RomHeader(program);
			product_code_string = String.format("%h", romHeader.productCode());
		} catch (Exception e){ }
		options.registerOption(Constants.OPTION_OVERRIDE_PRODUCT, product_code_string, null, "");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		String product_code_default_string = "0";
		try{
			RomHeader romHeader = new RomHeader(program);
			product_code_default_string = String.format("%h", romHeader.productCode());
		} catch (Exception e){ }
		
		mapper = options.getEnum(OPTION_MAPPER, MAPPER_DEFAULT_OPTION);
		apply_rom_data = options.getBoolean(Constants.OPTION_APPLY_ROM_DATA, true);
		ignore_checksum = options.getBoolean(Constants.OPTION_IGNORE_CHECKSUM, false);
		ignore_version = options.getBoolean(Constants.OPTION_IGNORE_VERSION, false);
		String product_code_string_value = options.getString(Constants.OPTION_OVERRIDE_PRODUCT, product_code_default_string);
		int product_code_int = -1;
		try {
			product_code_int = Integer.parseInt(product_code_string_value, 16);
		} catch (Exception e) {}
		override_product_version = product_code_int;
	}
	
	private static int getAddressString(Object op0) {
		Address op0_address = (Address) op0;
		String address_string = op0_address.toString(false);
		return Integer.parseInt(address_string, 16);
	}

}
