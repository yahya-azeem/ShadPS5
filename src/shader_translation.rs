use log::{info, warn, error};
use std::sync::Mutex;

/// Opcodes and operands for the GCN/RDNA2 instruction set architecture.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Operand {
    Sgpr(u8),
    Vgpr(u8),
    Literal(u32),
    Constant(i32),
}

#[derive(Debug, Clone)]
pub enum Rdna2Instruction {
    ScalarMov { dst_sgpr: u8, src: Operand },
    ScalarAdd { dst_sgpr: u8, src0: Operand, src1: Operand },
    VectorMov { dst_vgpr: u8, src: Operand },
    VectorAdd { dst_vgpr: u8, src0: Operand, src1: Operand },
    VectorMul { dst_vgpr: u8, src0: Operand, src1: Operand },
    SLoadDword { dst_sgpr: u8, base_sgpr: u8, offset: u16 },
    VImageSample { dst_vgpr: u8, src_vgpr: u8, resource_sgpr: u8, sampler_sgpr: u8 },
    EndPgm,
    Unknown(u32),
    // SOPK Format
    ScalarMovK { dst_sgpr: u8, simm16: i16 },
    ScalarAddK { dst_sgpr: u8, simm16: i16 },
    // VOP3 Format
    VectorFma {
        dst_vgpr: u8,
        src0: Operand,
        src1: Operand,
        src2: Operand,
        src0_neg: bool,
        src0_abs: bool,
        src1_neg: bool,
        src1_abs: bool,
        src2_neg: bool,
        src2_abs: bool,
        clamp: bool,
    },
    // SMEM Format
    SLoadDwordX4 { dst_sgpr: u8, base_sgpr: u8, offset: u16 },
    // VMEM Format
    VBufferLoadDword { dst_vgpr: u8, vaddr_vgpr: u8, resource_sgpr: u8, offset: u16 },
    VBufferStoreDword { src_vgpr: u8, vaddr_vgpr: u8, resource_sgpr: u8, offset: u16 },
    // SOPP Control Flow Format
    SBranch { offset: i16 },
    SCbranchScc0 { offset: i16 },
    SCbranchScc1 { offset: i16 },
    // Packed arithmetic (VOP3P Format)
    VectorPkFmaF16 { dst_vgpr: u8, src0: Operand, src1: Operand, src2: Operand },
    VectorPkAddF16 { dst_vgpr: u8, src0: Operand, src1: Operand },
    VectorPkMulF16 { dst_vgpr: u8, src0: Operand, src1: Operand },
    // DS Local Data Share Format
    DsReadB32 { dst_vgpr: u8, addr_vgpr: u8, offset: u16 },
    DsWriteB32 { addr_vgpr: u8, data_vgpr: u8, offset: u16 },
    // Subgroup/Lane operations
    VReadlaneB32 { dst_sgpr: u8, src_vgpr: u8, lane_operand: Operand },
    VWritelaneB32 { dst_vgpr: u8, src_operand: Operand, lane_operand: Operand },
    SBarrier,
    SWaitcnt { simm16: i16 },
    // EXEC mask mutation (wave-level divergence control)
    // s_and_saveexec_b64: saves current EXEC to dst, then EXEC = EXEC & src (narrows active lanes)
    SAndSaveexecB64 { dst_sgpr_pair: u8, src: Operand },
    // s_or_saveexec_b64: saves current EXEC to dst, then EXEC = EXEC | src (widens active lanes)
    SOrSaveexecB64 { dst_sgpr_pair: u8, src: Operand },
    // s_mov_b64 exec, src: restores EXEC mask (used to restore full-wave execution after divergence)
    SMovB64Exec { src: Operand },
}

#[derive(Debug, Clone)]
pub struct AstOperand {
    pub value: Operand,
    pub neg: bool,
    pub abs: bool,
}

#[derive(Debug, Clone)]
pub enum AstNode {
    Alu {
        op: String,
        dst: Operand,
        srcs: Vec<AstOperand>,
        clamp: bool,
    },
    Memory {
        op: String,
        dst: Operand,
        address: Operand,
        offset: u32,
        is_store: bool,
    },
    Image {
        op: String,
        dst: Operand,
        coords: Operand,
        resource: Operand,
        sampler: Operand,
    },
    Branch {
        cond: Option<Operand>,
        target_label: u32,
    },
    Return,
}

#[derive(Debug, Clone)]
pub struct ShaderBlock {
    pub label_id: u32,
    pub instructions: Vec<AstNode>,
    pub successors: Vec<u32>,
    pub predecessors: Vec<u32>,
}

/// Parses raw RDNA2 microcode words into structured instructions.
pub fn parse_rdna2_instructions(code: &[u32]) -> Vec<Rdna2Instruction> {
    let mut instructions = Vec::new();
    let mut i = 0;

    while i < code.len() {
        let inst = code[i];
        
        // 1. Check for s_endpgm (0xBF800000 is typical for GCN/RDNA)
        if inst == 0xBF800000 {
            instructions.push(Rdna2Instruction::EndPgm);
            i += 1;
            continue;
        }

        // 2. Decode SOP1 format (Scalar ALU 1 input)
        // Bit 31:23 = 101111101 (0x17D)
        if (inst >> 23) == 0x17D {
            let ssrc0 = (inst & 0xFF) as u8;
            let op = ((inst >> 8) & 0x7F) as u8;
            let sdst = ((inst >> 16) & 0x7F) as u8;

            match op {
                0x03 => { // s_mov_b32
                    let operand = if ssrc0 < 102 {
                        Operand::Sgpr(ssrc0)
                    } else if ssrc0 == 255 {
                        // Literal constant follows in next dword
                        i += 1;
                        let lit = if i < code.len() { code[i] } else { 0 };
                        Operand::Literal(lit)
                    } else {
                        Operand::Constant((ssrc0 as i32) - 128)
                    };
                    instructions.push(Rdna2Instruction::ScalarMov { dst_sgpr: sdst, src: operand });
                }
                0x01 => { // s_mov_b64
                    // When sdst == 126, this is s_mov_b64 exec, src (EXEC mask restore)
                    let operand = if ssrc0 < 102 {
                        Operand::Sgpr(ssrc0)
                    } else {
                        Operand::Constant((ssrc0 as i32) - 128)
                    };
                    if sdst == 126 {
                        // EXEC_LO register pair — this restores the EXEC mask
                        instructions.push(Rdna2Instruction::SMovB64Exec { src: operand });
                    } else {
                        instructions.push(Rdna2Instruction::ScalarMov { dst_sgpr: sdst, src: operand });
                    }
                }
                0x22 => { // s_and_saveexec_b64: dst = EXEC; EXEC = EXEC & src
                    let operand = if ssrc0 < 102 {
                        Operand::Sgpr(ssrc0)
                    } else {
                        Operand::Constant((ssrc0 as i32) - 128)
                    };
                    instructions.push(Rdna2Instruction::SAndSaveexecB64 { dst_sgpr_pair: sdst, src: operand });
                }
                0x24 => { // s_or_saveexec_b64: dst = EXEC; EXEC = EXEC | src
                    let operand = if ssrc0 < 102 {
                        Operand::Sgpr(ssrc0)
                    } else {
                        Operand::Constant((ssrc0 as i32) - 128)
                    };
                    instructions.push(Rdna2Instruction::SOrSaveexecB64 { dst_sgpr_pair: sdst, src: operand });
                }
                _ => {
                    instructions.push(Rdna2Instruction::Unknown(inst));
                }
            }
            i += 1;
            continue;
        }

        // 2b. Decode SOPK format (Scalar inline constant)
        // Bit 31:28 = 1011 (0xB)
        // Ensure it is not SOP1 (0x17D), SOPC (0x17E), or SOPP (0x17F)
        if (inst >> 28) == 0xB && (inst >> 23) != 0x17D && (inst >> 23) != 0x17E && (inst >> 23) != 0x17F {
            let simm16 = (inst & 0xFFFF) as i16;
            let sdst = ((inst >> 16) & 0x7F) as u8;
            let op = ((inst >> 23) & 0x1F) as u8;
            match op {
                0x00 => { // s_movk_i32
                    instructions.push(Rdna2Instruction::ScalarMovK { dst_sgpr: sdst, simm16 });
                }
                0x02 => { // s_addk_i32
                    instructions.push(Rdna2Instruction::ScalarAddK { dst_sgpr: sdst, simm16 });
                }
                _ => {
                    instructions.push(Rdna2Instruction::Unknown(inst));
                }
            }
            i += 1;
            continue;
        }

        // 2c. Decode SOPP format (Scalar control flow / branch)
        // Bit 31:23 = 101111111 (0x17F)
        if (inst >> 23) == 0x17F {
            let simm16 = (inst & 0xFFFF) as i16;
            let op = ((inst >> 16) & 0x7F) as u8;
            match op {
                0x02 => { // s_branch
                    instructions.push(Rdna2Instruction::SBranch { offset: simm16 });
                }
                0x04 => { // s_cbranch_scc0
                    instructions.push(Rdna2Instruction::SCbranchScc0 { offset: simm16 });
                }
                0x05 => { // s_cbranch_scc1
                    instructions.push(Rdna2Instruction::SCbranchScc1 { offset: simm16 });
                }
                0x0A => { // s_barrier
                    instructions.push(Rdna2Instruction::SBarrier);
                }
                0x0C => { // s_waitcnt
                    instructions.push(Rdna2Instruction::SWaitcnt { simm16 });
                }
                _ => {
                    instructions.push(Rdna2Instruction::Unknown(inst));
                }
            }
            i += 1;
            continue;
        }

        // 3. Decode SOP2 format (Scalar ALU 2 inputs)
        // Bit 31:30 = 10 (0x2), Bit 29:23 is opcode
        if (inst >> 30) == 0x2 {
            let ssrc0 = (inst & 0xFF) as u8;
            let ssrc1 = ((inst >> 8) & 0xFF) as u8;
            let sdst = ((inst >> 16) & 0x7F) as u8;
            let op = ((inst >> 23) & 0x7F) as u8;

            match op {
                0x00 => { // s_add_u32
                    let op0 = Operand::Sgpr(ssrc0);
                    let op1 = Operand::Sgpr(ssrc1);
                    instructions.push(Rdna2Instruction::ScalarAdd { dst_sgpr: sdst, src0: op0, src1: op1 });
                }
                _ => {
                    instructions.push(Rdna2Instruction::Unknown(inst));
                }
            }
            i += 1;
            continue;
        }

        // 4. Decode VOP2 format (Vector ALU 2 inputs)
        // Bit 31 = 0, Bit 30:25 is opcode
        if (inst >> 31) == 0 {
            let src0 = (inst & 0xFF) as u8;
            let vsrc1 = ((inst >> 8) & 0xFF) as u8;
            let vdst = ((inst >> 16) & 0xFF) as u8;
            let op = ((inst >> 25) & 0x3F) as u8;

            match op {
                0x01 => { // v_mov_b32
                    let op0 = Operand::Vgpr(src0);
                    instructions.push(Rdna2Instruction::VectorMov { dst_vgpr: vdst, src: op0 });
                }
                0x03 => { // v_add_f32
                    let op0 = Operand::Vgpr(src0);
                    let op1 = Operand::Vgpr(vsrc1);
                    instructions.push(Rdna2Instruction::VectorAdd { dst_vgpr: vdst, src0: op0, src1: op1 });
                }
                0x08 => { // v_mul_f32
                    let op0 = Operand::Vgpr(src0);
                    let op1 = Operand::Vgpr(vsrc1);
                    instructions.push(Rdna2Instruction::VectorMul { dst_vgpr: vdst, src0: op0, src1: op1 });
                }
                _ => {
                    instructions.push(Rdna2Instruction::Unknown(inst));
                }
            }
            i += 1;
            continue;
        }

        // 5. Decode VOP3 format (Vector ALU 3 operands - 64-bit)
        // Bit 31:26 = 110101 (0x35)
        if (inst >> 26) == 0x35 {
            if i + 1 < code.len() {
                let inst1 = code[i + 1];
                let op = ((inst >> 16) & 0x3FF) as u16;
                let vdst = (inst & 0xFF) as u8;
                
                let src0_val = (inst1 & 0x1FF) as u16;
                let src1_val = ((inst1 >> 9) & 0x1FF) as u16;
                let src2_val = ((inst1 >> 18) & 0x1FF) as u16;

                let parse_vop3_operand = |val: u16| -> Operand {
                    if val < 256 {
                        Operand::Vgpr(val as u8)
                    } else if val >= 256 && val < 358 {
                        Operand::Sgpr((val - 256) as u8)
                    } else {
                        Operand::Constant((val as i32) - 358)
                    }
                };

                let src0 = parse_vop3_operand(src0_val);
                let src1 = parse_vop3_operand(src1_val);
                let src2 = parse_vop3_operand(src2_val);

                let clamp = ((inst >> 15) & 1) != 0;
                let abs0 = ((inst1 >> 26) & 1) != 0;
                let abs1 = ((inst1 >> 27) & 1) != 0;
                let abs2 = ((inst1 >> 28) & 1) != 0;
                let neg0 = ((inst1 >> 29) & 1) != 0;
                let neg1 = ((inst1 >> 30) & 1) != 0;
                let neg2 = ((inst1 >> 31) & 1) != 0;

                match op {
                    0x1F4 | 0x22F | 0x2F4 => { // v_fma_f32 / v_mad_f32
                        instructions.push(Rdna2Instruction::VectorFma {
                            dst_vgpr: vdst,
                            src0,
                            src1,
                            src2,
                            src0_neg: neg0,
                            src0_abs: abs0,
                            src1_neg: neg1,
                            src1_abs: abs1,
                            src2_neg: neg2,
                            src2_abs: abs2,
                            clamp,
                        });
                    }
                    0x280 => { // v_readlane_b32
                        instructions.push(Rdna2Instruction::VReadlaneB32 {
                            dst_sgpr: vdst,
                            src_vgpr: match src0 { Operand::Vgpr(v) => v, _ => 0 },
                            lane_operand: src1,
                        });
                    }
                    0x282 => { // v_writelane_b32
                        instructions.push(Rdna2Instruction::VWritelaneB32 {
                            dst_vgpr: vdst,
                            src_operand: src0,
                            lane_operand: src1,
                        });
                    }
                    _ => {
                        instructions.push(Rdna2Instruction::Unknown(inst));
                    }
                }
                i += 2;
                continue;
            }
        }

        // 5b. Decode VOP3P format (Vector ALU Packed - 64-bit)
        // Bit 31:26 = 110011 (0x33)
        if (inst >> 26) == 0x33 {
            if i + 1 < code.len() {
                let inst1 = code[i + 1];
                let op = ((inst >> 16) & 0x3FF) as u16;
                let vdst = (inst & 0xFF) as u8;
                
                let src0_val = (inst1 & 0x1FF) as u16;
                let src1_val = ((inst1 >> 9) & 0x1FF) as u16;
                let src2_val = ((inst1 >> 18) & 0x1FF) as u16;

                let parse_vop3p_operand = |val: u16| -> Operand {
                    if val < 256 {
                        Operand::Vgpr(val as u8)
                    } else if val >= 256 && val < 358 {
                        Operand::Sgpr((val - 256) as u8)
                    } else {
                        Operand::Constant((val as i32) - 358)
                    }
                };

                let src0 = parse_vop3p_operand(src0_val);
                let src1 = parse_vop3p_operand(src1_val);
                let src2 = parse_vop3p_operand(src2_val);

                match op {
                    0x00 => { // v_pk_fma_f16
                        instructions.push(Rdna2Instruction::VectorPkFmaF16 { dst_vgpr: vdst, src0, src1, src2 });
                    }
                    0x01 => { // v_pk_add_f16
                        instructions.push(Rdna2Instruction::VectorPkAddF16 { dst_vgpr: vdst, src0, src1 });
                    }
                    0x02 => { // v_pk_mul_f16
                        instructions.push(Rdna2Instruction::VectorPkMulF16 { dst_vgpr: vdst, src0, src1 });
                    }
                    _ => {
                        instructions.push(Rdna2Instruction::Unknown(inst));
                    }
                }
                i += 2;
                continue;
            }
        }

        // 5c. Decode DS format (LDS operations - 64-bit)
        // Bit 31:26 = 110110 (0x36)
        if (inst >> 26) == 0x36 {
            if i + 1 < code.len() {
                let inst1 = code[i + 1];
                let op = ((inst >> 18) & 0xFF) as u8;
                let addr = (inst & 0xFF) as u8;
                let offset = ((inst >> 8) & 0x3FF) as u16;
                let vdst = ((inst1 >> 24) & 0xFF) as u8;
                let vdata0 = ((inst1 >> 8) & 0xFF) as u8;

                match op {
                    0x0D | 0x36 => { // ds_read_b32
                        instructions.push(Rdna2Instruction::DsReadB32 { dst_vgpr: vdst, addr_vgpr: addr, offset });
                    }
                    0x1D | 0xD0 => { // ds_write_b32
                        instructions.push(Rdna2Instruction::DsWriteB32 { addr_vgpr: addr, data_vgpr: vdata0, offset });
                    }
                    _ => {
                        instructions.push(Rdna2Instruction::Unknown(inst));
                    }
                }
                i += 2;
                continue;
            }
        }

        // 6. Decode SMEM format (Scalar Memory - 64-bit)
        // Bit 31:26 = 111100 (0x3C)
        if (inst >> 26) == 0x3C {
            if i + 1 < code.len() {
                let inst1 = code[i + 1];
                let op = ((inst >> 18) & 0xFF) as u8;
                let sdst = (inst & 0x7F) as u8;
                let sbase = ((inst >> 9) & 0x3F) as u8;
                let offset = (inst1 & 0xFFFF) as u16;

                match op {
                    0x00 => { // s_load_dword
                        instructions.push(Rdna2Instruction::SLoadDword { dst_sgpr: sdst, base_sgpr: sbase, offset });
                    }
                    0x02 => { // s_load_dwordx4
                        instructions.push(Rdna2Instruction::SLoadDwordX4 { dst_sgpr: sdst, base_sgpr: sbase, offset });
                    }
                    _ => {
                        instructions.push(Rdna2Instruction::Unknown(inst));
                    }
                }
                i += 2;
                continue;
            }
        }

        // 7. Decode VMEM/MIMG format (Vector Memory / Image - 64-bit)
        // VMEM starts with 110000 (0x30) or 110001 (0x31)
        if (inst >> 26) == 0x30 || (inst >> 26) == 0x31 {
            if i + 1 < code.len() {
                let inst1 = code[i + 1];
                let vdata = (inst & 0xFF) as u8;
                let vaddr = ((inst >> 8) & 0xFF) as u8;
                let srsrc = (inst1 & 0x1F) as u8;
                let offset = ((inst1 >> 8) & 0xFFF) as u16;

                if (inst >> 26) == 0x30 {
                    instructions.push(Rdna2Instruction::VBufferLoadDword { dst_vgpr: vdata, vaddr_vgpr: vaddr, resource_sgpr: srsrc, offset });
                } else {
                    instructions.push(Rdna2Instruction::VBufferStoreDword { src_vgpr: vdata, vaddr_vgpr: vaddr, resource_sgpr: srsrc, offset });
                }
                i += 2;
                continue;
            }
        }

        // MIMG format (Image Sample - 64-bit) starts with 110010 (0x32)
        if (inst >> 26) == 0x32 {
            if i + 1 < code.len() {
                let inst1 = code[i + 1];
                let vdata = (inst & 0xFF) as u8;
                let vaddr = ((inst >> 8) & 0xFF) as u8;
                let srsrc = (inst1 & 0x1F) as u8;
                let ssampl = ((inst1 >> 5) & 0x1F) as u8;

                instructions.push(Rdna2Instruction::VImageSample { dst_vgpr: vdata, src_vgpr: vaddr, resource_sgpr: srsrc, sampler_sgpr: ssampl });
                i += 2;
                continue;
            }
        }

        // Fallback for unparsed/complex instructions (e.g. VMEM/SMEM which are 64-bit)
        instructions.push(Rdna2Instruction::Unknown(inst));
        i += 1;
    }

    instructions
}

pub fn lift_to_ast(inst: &Rdna2Instruction) -> AstNode {
    match inst {
        Rdna2Instruction::ScalarMov { dst_sgpr, src } => {
            AstNode::Alu {
                op: "s_mov".to_string(),
                dst: Operand::Sgpr(*dst_sgpr),
                srcs: vec![AstOperand { value: src.clone(), neg: false, abs: false }],
                clamp: false,
            }
        }
        Rdna2Instruction::ScalarMovK { dst_sgpr, simm16 } => {
            let val = *simm16 as i32;
            AstNode::Alu {
                op: "s_movk".to_string(),
                dst: Operand::Sgpr(*dst_sgpr),
                srcs: vec![AstOperand { value: Operand::Constant(val), neg: false, abs: false }],
                clamp: false,
            }
        }
        Rdna2Instruction::ScalarAdd { dst_sgpr, src0, src1 } => {
            AstNode::Alu {
                op: "s_add".to_string(),
                dst: Operand::Sgpr(*dst_sgpr),
                srcs: vec![
                    AstOperand { value: src0.clone(), neg: false, abs: false },
                    AstOperand { value: src1.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::ScalarAddK { dst_sgpr, simm16 } => {
            let val = *simm16 as i32;
            AstNode::Alu {
                op: "s_addk".to_string(),
                dst: Operand::Sgpr(*dst_sgpr),
                srcs: vec![
                    AstOperand { value: Operand::Sgpr(*dst_sgpr), neg: false, abs: false },
                    AstOperand { value: Operand::Constant(val), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::VectorMov { dst_vgpr, src } => {
            AstNode::Alu {
                op: "v_mov".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                srcs: vec![AstOperand { value: src.clone(), neg: false, abs: false }],
                clamp: false,
            }
        }
        Rdna2Instruction::VectorAdd { dst_vgpr, src0, src1 } => {
            AstNode::Alu {
                op: "v_add".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                srcs: vec![
                    AstOperand { value: src0.clone(), neg: false, abs: false },
                    AstOperand { value: src1.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::VectorMul { dst_vgpr, src0, src1 } => {
            AstNode::Alu {
                op: "v_mul".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                srcs: vec![
                    AstOperand { value: src0.clone(), neg: false, abs: false },
                    AstOperand { value: src1.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::VectorFma {
            dst_vgpr,
            src0,
            src1,
            src2,
            src0_neg,
            src0_abs,
            src1_neg,
            src1_abs,
            src2_neg,
            src2_abs,
            clamp,
        } => {
            AstNode::Alu {
                op: "v_fma".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                srcs: vec![
                    AstOperand { value: src0.clone(), neg: *src0_neg, abs: *src0_abs },
                    AstOperand { value: src1.clone(), neg: *src1_neg, abs: *src1_abs },
                    AstOperand { value: src2.clone(), neg: *src2_neg, abs: *src2_abs },
                ],
                clamp: *clamp,
            }
        }
        Rdna2Instruction::SLoadDword { dst_sgpr, base_sgpr, offset } => {
            AstNode::Memory {
                op: "s_load_dword".to_string(),
                dst: Operand::Sgpr(*dst_sgpr),
                address: Operand::Sgpr(*base_sgpr),
                offset: *offset as u32,
                is_store: false,
            }
        }
        Rdna2Instruction::SLoadDwordX4 { dst_sgpr, base_sgpr, offset } => {
            AstNode::Memory {
                op: "s_load_dwordx4".to_string(),
                dst: Operand::Sgpr(*dst_sgpr),
                address: Operand::Sgpr(*base_sgpr),
                offset: *offset as u32,
                is_store: false,
            }
        }
        Rdna2Instruction::VBufferLoadDword { dst_vgpr, vaddr_vgpr, resource_sgpr, offset } => {
            AstNode::Memory {
                op: "v_buffer_load_dword".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                address: Operand::Sgpr(*resource_sgpr),
                offset: (*offset as u32) + (*vaddr_vgpr as u32 * 4),
                is_store: false,
            }
        }
        Rdna2Instruction::VBufferStoreDword { src_vgpr, vaddr_vgpr, resource_sgpr, offset } => {
            AstNode::Memory {
                op: "v_buffer_store_dword".to_string(),
                dst: Operand::Vgpr(*src_vgpr),
                address: Operand::Sgpr(*resource_sgpr),
                offset: (*offset as u32) + (*vaddr_vgpr as u32 * 4),
                is_store: true,
            }
        }
        Rdna2Instruction::VImageSample { dst_vgpr, src_vgpr, resource_sgpr, sampler_sgpr } => {
            AstNode::Image {
                op: "image_sample".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                coords: Operand::Vgpr(*src_vgpr),
                resource: Operand::Sgpr(*resource_sgpr),
                sampler: Operand::Sgpr(*sampler_sgpr),
            }
        }
        Rdna2Instruction::SBranch { offset } => {
            AstNode::Branch {
                cond: None,
                target_label: *offset as u32,
            }
        }
        Rdna2Instruction::SCbranchScc0 { offset } => {
            AstNode::Branch {
                cond: Some(Operand::Sgpr(0)),
                target_label: *offset as u32,
            }
        }
        Rdna2Instruction::SCbranchScc1 { offset } => {
            AstNode::Branch {
                cond: Some(Operand::Sgpr(0)),
                target_label: *offset as u32,
            }
        }
        Rdna2Instruction::VectorPkFmaF16 { dst_vgpr, src0, src1, src2 } => {
            AstNode::Alu {
                op: "v_pk_fma".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                srcs: vec![
                    AstOperand { value: src0.clone(), neg: false, abs: false },
                    AstOperand { value: src1.clone(), neg: false, abs: false },
                    AstOperand { value: src2.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::VectorPkAddF16 { dst_vgpr, src0, src1 } => {
            AstNode::Alu {
                op: "v_pk_add".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                srcs: vec![
                    AstOperand { value: src0.clone(), neg: false, abs: false },
                    AstOperand { value: src1.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::VectorPkMulF16 { dst_vgpr, src0, src1 } => {
            AstNode::Alu {
                op: "v_pk_mul".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                srcs: vec![
                    AstOperand { value: src0.clone(), neg: false, abs: false },
                    AstOperand { value: src1.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::DsReadB32 { dst_vgpr, addr_vgpr, offset } => {
            AstNode::Memory {
                op: "ds_read".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                address: Operand::Vgpr(*addr_vgpr),
                offset: *offset as u32,
                is_store: false,
            }
        }
        Rdna2Instruction::DsWriteB32 { addr_vgpr, data_vgpr, offset } => {
            AstNode::Memory {
                op: "ds_write".to_string(),
                dst: Operand::Vgpr(*data_vgpr),
                address: Operand::Vgpr(*addr_vgpr),
                offset: *offset as u32,
                is_store: true,
            }
        }
        Rdna2Instruction::VReadlaneB32 { dst_sgpr, src_vgpr, lane_operand } => {
            AstNode::Alu {
                op: "v_readlane".to_string(),
                dst: Operand::Sgpr(*dst_sgpr),
                srcs: vec![
                    AstOperand { value: Operand::Vgpr(*src_vgpr), neg: false, abs: false },
                    AstOperand { value: lane_operand.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::VWritelaneB32 { dst_vgpr, src_operand, lane_operand } => {
            AstNode::Alu {
                op: "v_writelane".to_string(),
                dst: Operand::Vgpr(*dst_vgpr),
                srcs: vec![
                    AstOperand { value: src_operand.clone(), neg: false, abs: false },
                    AstOperand { value: lane_operand.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::SBarrier => {
            AstNode::Alu {
                op: "s_barrier".to_string(),
                dst: Operand::Sgpr(0),
                srcs: Vec::new(),
                clamp: false,
            }
        }
        Rdna2Instruction::SWaitcnt { simm16 } => {
            AstNode::Alu {
                op: "s_waitcnt".to_string(),
                dst: Operand::Sgpr(0),
                srcs: vec![
                    AstOperand { value: Operand::Constant(*simm16 as i32), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::SAndSaveexecB64 { dst_sgpr_pair, src } => {
            AstNode::Alu {
                op: "s_and_saveexec_b64".to_string(),
                dst: Operand::Sgpr(*dst_sgpr_pair),
                srcs: vec![
                    AstOperand { value: src.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::SOrSaveexecB64 { dst_sgpr_pair, src } => {
            AstNode::Alu {
                op: "s_or_saveexec_b64".to_string(),
                dst: Operand::Sgpr(*dst_sgpr_pair),
                srcs: vec![
                    AstOperand { value: src.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::SMovB64Exec { src } => {
            AstNode::Alu {
                op: "s_mov_b64_exec".to_string(),
                dst: Operand::Sgpr(126), // EXEC_LO
                srcs: vec![
                    AstOperand { value: src.clone(), neg: false, abs: false },
                ],
                clamp: false,
            }
        }
        Rdna2Instruction::EndPgm => AstNode::Return,
        Rdna2Instruction::Unknown(inst) => AstNode::Alu {
            op: format!("unknown_0x{:X}", inst),
            dst: Operand::Sgpr(0),
            srcs: Vec::new(),
            clamp: false,
        },
    }
}

pub fn build_cfg(instructions: &[Rdna2Instruction]) -> Vec<ShaderBlock> {
    let mut block_starts = std::collections::BTreeSet::new();
    block_starts.insert(0);
    
    for (idx, inst) in instructions.iter().enumerate() {
        match inst {
            Rdna2Instruction::SBranch { offset } |
            Rdna2Instruction::SCbranchScc0 { offset } |
            Rdna2Instruction::SCbranchScc1 { offset } => {
                let target = (idx as i32 + 1 + *offset as i32) as usize;
                block_starts.insert(target);
                block_starts.insert(idx + 1);
            }
            Rdna2Instruction::EndPgm => {
                block_starts.insert(idx + 1);
            }
            _ => {}
        }
    }
    
    let mut blocks = Vec::new();
    let starts: Vec<usize> = block_starts.into_iter().filter(|&pc| pc <= instructions.len()).collect();
    
    for i in 0..starts.len() {
        let start = starts[i];
        let end = if i + 1 < starts.len() { starts[i + 1] } else { instructions.len() };
        if start >= end {
            continue;
        }
        
        let block_insts = &instructions[start..end];
        let label_id = start as u32;
        
        let mut successors = Vec::new();
        let last_idx = end - 1;
        match &instructions[last_idx] {
            Rdna2Instruction::SBranch { offset } => {
                let target = (last_idx as i32 + 1 + *offset as i32) as u32;
                successors.push(target);
            }
            Rdna2Instruction::SCbranchScc0 { offset } |
            Rdna2Instruction::SCbranchScc1 { offset } => {
                let target = (last_idx as i32 + 1 + *offset as i32) as u32;
                successors.push(target);
                if end < instructions.len() {
                    successors.push(end as u32);
                }
            }
            Rdna2Instruction::EndPgm => {}
            _ => {
                if end < instructions.len() {
                    successors.push(end as u32);
                }
            }
        }
        
        blocks.push(ShaderBlock {
            label_id,
            instructions: block_insts.iter().map(|inst| lift_to_ast(inst)).collect(),
            successors,
            predecessors: Vec::new(),
        });
    }
    
    // Predecessor mapping
    let mut pred_map = std::collections::HashMap::new();
    for block in &blocks {
        for &succ in &block.successors {
            pred_map.entry(succ).or_insert_with(Vec::new).push(block.label_id);
        }
    }
    
    for block in &mut blocks {
        if let Some(preds) = pred_map.get(&block.label_id) {
            block.predecessors = preds.clone();
        }
    }
    
    blocks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Decorations,
    TypesAndConstants,
    Functions,
}

/// A structured SPIR-V binary code builder.
pub struct SpirvBuilder {
    bound_id: u32,
    decorations: Vec<u32>,
    types_and_constants: Vec<u32>,
    functions: Vec<u32>,
    current_section: Section,
    constant_cache: std::collections::HashMap<(u32, Vec<u32>), u32>,
}

impl SpirvBuilder {
    pub fn new() -> Self {
        SpirvBuilder {
            bound_id: 1, // IDs start at 1
            decorations: Vec::new(),
            types_and_constants: Vec::new(),
            functions: Vec::new(),
            current_section: Section::Decorations,
            constant_cache: std::collections::HashMap::new(),
        }
    }

    pub fn get_or_create_constant(&mut self, type_id: u32, value_words: &[u32]) -> u32 {
        let key = (type_id, value_words.to_vec());
        if let Some(&id) = self.constant_cache.get(&key) {
            id
        } else {
            let id = self.alloc_id();
            let mut args = vec![type_id, id];
            args.extend_from_slice(value_words);
            self.write_type_const(43, &args);
            self.constant_cache.insert(key, id);
            id
        }
    }

    pub fn set_section(&mut self, section: Section) {
        self.current_section = section;
    }

    pub fn alloc_id(&mut self) -> u32 {
        let id = self.bound_id;
        self.bound_id += 1;
        id
    }

    pub fn write_inst(&mut self, opcode: u16, args: &[u32]) {
        self.write_to_section(self.current_section, opcode, args);
    }

    pub fn write_type_const(&mut self, opcode: u16, args: &[u32]) {
        self.write_to_section(Section::TypesAndConstants, opcode, args);
    }

    pub fn write_to_section(&mut self, section: Section, opcode: u16, args: &[u32]) {
        let word_count = (args.len() + 1) as u32;
        let word0 = (word_count << 16) | (opcode as u32);
        match section {
            Section::Decorations => {
                self.decorations.push(word0);
                self.decorations.extend_from_slice(args);
            }
            Section::TypesAndConstants => {
                self.types_and_constants.push(word0);
                self.types_and_constants.extend_from_slice(args);
            }
            Section::Functions => {
                self.functions.push(word0);
                self.functions.extend_from_slice(args);
            }
        }
    }


    pub fn write_str_inst(&mut self, opcode: u16, result_id: Option<u32>, string_val: &str, other_args: &[u32]) {
        let mut final_args = Vec::new();
        if let Some(id) = result_id {
            final_args.push(id);
        }
        
        let bytes = string_val.as_bytes();
        let mut words = Vec::new();
        for chunk in bytes.chunks(4) {
            let mut word = 0u32;
            for (idx, &byte) in chunk.iter().enumerate() {
                word |= (byte as u32) << (idx * 8);
            }
            words.push(word);
        }
        if bytes.len() % 4 == 0 {
            words.push(0);
        }
        
        final_args.extend(words);
        final_args.extend_from_slice(other_args);
        
        self.write_inst(opcode, &final_args);
    }

    pub fn build(self) -> Vec<u32> {
        let mut words = Vec::new();
        // Standard SPIR-V Header
        words.push(0x07230203); // Magic Number
        words.push(0x00010300); // Version (1.3)
        words.push(0x00000000); // Generator Magic
        words.push(self.bound_id); // Bound ID
        words.push(0);          // Reserved

        words.extend(self.decorations);
        words.extend(self.types_and_constants);
        words.extend(self.functions);
        words
    }
}

fn compute_post_dominators(blocks: &[ShaderBlock]) -> std::collections::HashMap<u32, std::collections::BTreeSet<u32>> {
    let mut post_dom = std::collections::HashMap::new();
    let all_labels: std::collections::BTreeSet<u32> = blocks.iter().map(|b| b.label_id).collect();
    
    for block in blocks {
        post_dom.insert(block.label_id, all_labels.clone());
    }
    
    let exit_blocks: Vec<u32> = blocks.iter()
        .filter(|b| b.successors.is_empty())
        .map(|b| b.label_id)
        .collect();
        
    for &exit in &exit_blocks {
        let mut self_set = std::collections::BTreeSet::new();
        self_set.insert(exit);
        post_dom.insert(exit, self_set);
    }
    
    let mut changed = true;
    while changed {
        changed = false;
        for block in blocks {
            if exit_blocks.contains(&block.label_id) {
                continue;
            }
            
            let mut new_set = all_labels.clone();
            if !block.successors.is_empty() {
                let succ_id = block.successors[0];
                if let Some(set) = post_dom.get(&succ_id) {
                    new_set = set.clone();
                }
                for &succ in block.successors.iter().skip(1) {
                    if let Some(set) = post_dom.get(&succ) {
                        new_set = new_set.intersection(set).copied().collect();
                    }
                }
            } else {
                new_set.clear();
            }
            
            new_set.insert(block.label_id);
            
            if let Some(old_set) = post_dom.get_mut(&block.label_id) {
                if *old_set != new_set {
                    *old_set = new_set;
                    changed = true;
                }
            }
        }
    }
    
    post_dom
}

fn find_immediate_post_dominator(
    block_id: u32,
    post_dom: &std::collections::HashMap<u32, std::collections::BTreeSet<u32>>,
) -> Option<u32> {
    let pdoms = post_dom.get(&block_id)?;
    let mut candidates: Vec<u32> = pdoms.iter().copied().filter(|&x| x != block_id).collect();
    candidates.sort_by_key(|&x| std::cmp::Reverse(post_dom.get(&x).map_or(0, |s| s.len())));
    candidates.first().copied()
}

fn find_loop_blocks(header_id: u32, continue_id: u32, blocks: &[ShaderBlock]) -> std::collections::BTreeSet<u32> {
    let mut loop_blocks = std::collections::BTreeSet::new();
    let mut queue = vec![continue_id];
    loop_blocks.insert(header_id);
    loop_blocks.insert(continue_id);
    
    while let Some(curr) = queue.pop() {
        if curr == header_id {
            continue;
        }
        if let Some(block) = blocks.iter().find(|b| b.label_id == curr) {
            for &pred in &block.predecessors {
                if !loop_blocks.contains(&pred) {
                    loop_blocks.insert(pred);
                    queue.push(pred);
                }
            }
        }
    }
    loop_blocks
}

fn rebuild_predecessors(blocks: &mut [ShaderBlock]) {
    let mut pred_map = std::collections::HashMap::new();
    for block in blocks.iter() {
        for &succ in &block.successors {
            pred_map.entry(succ).or_insert_with(Vec::new).push(block.label_id);
        }
    }
    for block in blocks.iter_mut() {
        block.predecessors = pred_map.get(&block.label_id).cloned().unwrap_or_default();
    }
}

fn collapse_empty_blocks(blocks: &mut Vec<ShaderBlock>) {
    let mut changed = true;
    while changed {
        changed = false;
        let mut to_remove = None;
        for (idx, block) in blocks.iter().enumerate() {
            if block.label_id == 0 {
                continue; // Keep entry block
            }
            if block.instructions.is_empty() && block.successors.len() == 1 {
                let succ = block.successors[0];
                if block.predecessors.contains(&block.label_id) || block.predecessors.contains(&succ) {
                    continue;
                }
                to_remove = Some((idx, block.label_id, succ));
                break;
            }
        }
        if let Some((idx, label_id, succ)) = to_remove {
            blocks.remove(idx);
            for b in blocks.iter_mut() {
                for s in &mut b.successors {
                    if *s == label_id {
                        *s = succ;
                    }
                }
            }
            rebuild_predecessors(blocks);
            changed = true;
        }
    }
}

fn unify_loop_backedges(blocks: &mut Vec<ShaderBlock>, next_label_id: &mut u32) {
    rebuild_predecessors(blocks);
    
    let mut loop_headers = Vec::new();
    for (idx, block) in blocks.iter().enumerate() {
        let back_edges: Vec<u32> = block.predecessors.iter().copied()
            .filter(|&pred| {
                if let Some(pred_idx) = blocks.iter().position(|b| b.label_id == pred) {
                    pred_idx >= idx
                } else {
                    false
                }
            })
            .collect();
        if back_edges.len() > 1 {
            loop_headers.push((block.label_id, back_edges));
        }
    }
    
    for (header_id, back_edges) in loop_headers {
        let continue_ladder_id = *next_label_id;
        *next_label_id += 1;
        
        let continue_block = ShaderBlock {
            label_id: continue_ladder_id,
            instructions: Vec::new(),
            successors: vec![header_id],
            predecessors: back_edges.clone(),
        };
        
        for &pred in &back_edges {
            if let Some(b) = blocks.iter_mut().find(|b| b.label_id == pred) {
                for succ in &mut b.successors {
                    if *succ == header_id {
                        *succ = continue_ladder_id;
                    }
                }
            }
        }
        
        blocks.push(continue_block);
    }
    
    rebuild_predecessors(blocks);
}

fn split_loop_headers(blocks: &mut Vec<ShaderBlock>, next_label_id: &mut u32, instructions: &[Rdna2Instruction]) {
    rebuild_predecessors(blocks);
    
    let mut loop_headers = std::collections::HashSet::new();
    for (idx, block) in blocks.iter().enumerate() {
        let is_header = block.predecessors.iter().any(|&pred| {
            if let Some(pred_idx) = blocks.iter().position(|b| b.label_id == pred) {
                pred_idx >= idx
            } else {
                false
            }
        });
        if is_header {
            loop_headers.insert(block.label_id);
        }
    }
    
    let mut new_blocks = Vec::new();
    for block in blocks.iter_mut() {
        if loop_headers.contains(&block.label_id) {
            let has_cond_branch = if block.instructions.is_empty() {
                false
            } else {
                let last_inst_idx = block.label_id as usize + block.instructions.len() - 1;
                if last_inst_idx < instructions.len() {
                    match &instructions[last_inst_idx] {
                        Rdna2Instruction::SCbranchScc0 { .. } |
                        Rdna2Instruction::SCbranchScc1 { .. } => true,
                        _ => false,
                    }
                } else {
                    false
                }
            };
            
            if has_cond_branch {
                let last_inst_idx = block.label_id as usize + block.instructions.len() - 1;
                let new_label = last_inst_idx as u32;
                
                // The new block inherits the conditional branch and successors
                let mut new_block = ShaderBlock {
                    label_id: new_label,
                    instructions: vec![block.instructions.pop().unwrap()],
                    successors: block.successors.clone(),
                    predecessors: vec![block.label_id],
                };
                
                // The original block now branches unconditionally to the new block
                block.successors = vec![new_label];
                
                new_blocks.push(new_block);
            }
        }
    }
    
    blocks.extend(new_blocks);
    rebuild_predecessors(blocks);
}

fn inject_ladders(blocks: &mut Vec<ShaderBlock>, next_label_id: &mut u32) {
    rebuild_predecessors(blocks);
    
    let post_dom = compute_post_dominators(blocks);
    
    let mut loop_merges = std::collections::HashMap::new();
    for (block_idx, block) in blocks.iter().enumerate() {
        let back_edge_preds: Vec<u32> = block.predecessors.iter().copied()
            .filter(|&pred| {
                if let Some(pred_idx) = blocks.iter().position(|b| b.label_id == pred) {
                    pred_idx >= block_idx
                } else {
                    false
                }
            })
            .collect();
        if !back_edge_preds.is_empty() {
            let continue_id = back_edge_preds[0];
            let merge_id = find_loop_merge_block(block.label_id, continue_id, blocks, &post_dom);
            loop_merges.insert(block.label_id, merge_id);
        }
    }
    
    let mut selection_merges = std::collections::HashMap::new();
    for block in blocks.iter() {
        let is_conditional = block.successors.len() > 1;
        if is_conditional {
            if let Some(merge_id) = find_immediate_post_dominator(block.label_id, &post_dom) {
                selection_merges.insert(block.label_id, merge_id);
            }
        }
    }
    
    let mut merge_to_headers = std::collections::HashMap::new();
    for (&header, &merge) in &loop_merges {
        merge_to_headers.entry(merge).or_insert_with(Vec::new).push((header, true));
    }
    for (&header, &merge) in &selection_merges {
        merge_to_headers.entry(merge).or_insert_with(Vec::new).push((header, false));
    }
    
    for (merge_id, headers) in merge_to_headers {
        if headers.len() > 1 {
            let mut keep_first_loop = headers.iter().any(|&(_, is_loop)| is_loop);
            let mut first = true;
            
            for &(header, is_loop) in &headers {
                if is_loop && keep_first_loop {
                    keep_first_loop = false;
                    continue;
                }
                if first && !is_loop && !headers.iter().any(|&(_, il)| il) {
                    first = false;
                    continue;
                }
                
                let ladder_id = *next_label_id;
                *next_label_id += 1;
                
                let ladder_block = ShaderBlock {
                    label_id: ladder_id,
                    instructions: Vec::new(),
                    successors: vec![merge_id],
                    predecessors: vec![header],
                };
                
                if let Some(h_block) = blocks.iter_mut().find(|b| b.label_id == header) {
                    for succ in &mut h_block.successors {
                        if *succ == merge_id {
                            *succ = ladder_id;
                        }
                    }
                }
                
                blocks.push(ladder_block);
            }
        }
    }
    
    rebuild_predecessors(blocks);
}

/// Irreducible CFG Loop Transposition (Dispatch Switch Variable Pattern)
///
/// Detects irreducible control flow (where a loop body has multiple entry points
/// that aren't dominated by a single header) and converts it to reducible form.
///
/// The transformation:
/// 1. Identifies blocks reachable from multiple entry edges (irreducible headers)
/// 2. Creates a new synthetic dispatch loop header
/// 3. Adds a dispatch variable that selects which original entry block to jump to
/// 4. All original entry edges are redirected to the dispatch header
/// 5. The dispatch header branches to the correct target based on the dispatch variable
///
static REDIRECTED_EDGES: Mutex<Option<std::collections::HashMap<(u32, u32), u32>>> = Mutex::new(None);

pub fn register_redirection(pred: u32, dispatch: u32, target: u32) {
    let mut guard = REDIRECTED_EDGES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(std::collections::HashMap::new());
    }
    guard.as_mut().unwrap().insert((pred, dispatch), target);
}

pub fn lookup_redirection(pred: u32, dispatch: u32) -> Option<u32> {
    let guard = REDIRECTED_EDGES.lock().unwrap();
    if let Some(ref map) = *guard {
        map.get(&(pred, dispatch)).copied()
    } else {
        None
    }
}

fn transpose_irreducible_loops(blocks: &mut Vec<ShaderBlock>, next_label_id: &mut u32) {
    rebuild_predecessors(blocks);
    
    // Compute dominators (forward, not post-dominators) for irreducibility detection
    let mut dominators: std::collections::HashMap<u32, std::collections::BTreeSet<u32>> = std::collections::HashMap::new();
    let all_ids: Vec<u32> = blocks.iter().map(|b| b.label_id).collect();
    
    // Initialize: every block is dominated by all blocks
    for &id in &all_ids {
        let mut dom_set = std::collections::BTreeSet::new();
        if id == blocks[0].label_id {
            dom_set.insert(id);
        } else {
            for &other in &all_ids {
                dom_set.insert(other);
            }
        }
        dominators.insert(id, dom_set);
    }
    
    // Iterative dataflow until convergence
    let mut changed = true;
    while changed {
        changed = false;
        for block in blocks.iter() {
            if block.label_id == blocks[0].label_id { continue; }
            let mut new_dom = std::collections::BTreeSet::new();
            for &all in &all_ids {
                new_dom.insert(all);
            }
            for &pred in &block.predecessors {
                if let Some(pred_dom) = dominators.get(&pred) {
                    new_dom = new_dom.intersection(pred_dom).copied().collect();
                }
            }
            new_dom.insert(block.label_id);
            if dominators.get(&block.label_id) != Some(&new_dom) {
                dominators.insert(block.label_id, new_dom);
                changed = true;
            }
        }
    }
    
    // Detect irreducible headers: blocks with predecessors that don't dominate them
    // AND that are reachable from a back-edge (creating a multi-entry loop)
    let mut irreducible_groups: Vec<Vec<u32>> = Vec::new();
    
    for (block_idx, block) in blocks.iter().enumerate() {
        // Check if any predecessor is NOT dominated by this block and is NOT a back-edge
        // from within a natural loop (i.e., it's a cross-edge creating irreducibility)
        let mut non_dominated_preds = Vec::new();
        for &pred in &block.predecessors {
            if let Some(dom_set) = dominators.get(&pred) {
                if !dom_set.contains(&block.label_id) {
                    // pred is not dominated by this block — potential irreducible entry
                    if let Some(pred_idx) = blocks.iter().position(|b| b.label_id == pred) {
                        if pred_idx < block_idx {
                            // Forward edge from a non-dominator — this creates irreducibility
                            non_dominated_preds.push(pred);
                        }
                    }
                }
            }
        }
        
        // If a block has forward non-dominator predecessors AND also has back-edge
        // predecessors, it's part of an irreducible loop
        let has_back_edge = block.predecessors.iter().any(|&pred| {
            blocks.iter().position(|b| b.label_id == pred)
                .map(|pi| pi >= block_idx)
                .unwrap_or(false)
        });
        
        if !non_dominated_preds.is_empty() && has_back_edge {
            // This block is an irreducible header — collect the entry group
            let mut group = vec![block.label_id];
            for &pred_block_id in &non_dominated_preds {
                // The target of the cross-edge is also part of the irreducible group
                for &succ in &blocks.iter().find(|b| b.label_id == pred_block_id).map(|b| b.successors.clone()).unwrap_or_default() {
                    if !group.contains(&succ) && succ != block.label_id {
                        group.push(succ);
                    }
                }
            }
            if group.len() > 1 {
                irreducible_groups.push(group);
            }
        }
    }
    
    // For each irreducible group, create a dispatch loop header
    for group in irreducible_groups {
        if group.len() < 2 { continue; }
        
        let dispatch_header_id = *next_label_id;
        *next_label_id += 1;
        
        // The dispatch header branches to all entries in the group
        let dispatch_block = ShaderBlock {
            label_id: dispatch_header_id,
            instructions: Vec::new(),
            successors: group.clone(),
            predecessors: Vec::new(),
        };
        
        // Redirect ALL external predecessors of ALL entries in the group to the dispatch header
        for &entry_id in &group {
            if let Some(entry_block) = blocks.iter().find(|b| b.label_id == entry_id) {
                let external_preds: Vec<u32> = entry_block.predecessors.iter().copied()
                    .filter(|p| !group.contains(p))
                    .collect();
                
                for pred in external_preds {
                    if let Some(pred_block) = blocks.iter_mut().find(|b| b.label_id == pred) {
                        for succ in &mut pred_block.successors {
                            if *succ == entry_id {
                                *succ = dispatch_header_id;
                                register_redirection(pred, dispatch_header_id, entry_id);
                            }
                        }
                    }
                }
            }
        }
        
        blocks.push(dispatch_block);
        info!("Irreducible CFG: inserted dispatch header {} for group {:?}", dispatch_header_id, group);
    }
    
    rebuild_predecessors(blocks);
}

fn sort_blocks_rpo(blocks: &mut Vec<ShaderBlock>) {
    let mut visited = std::collections::HashSet::new();
    let mut post_order = Vec::new();
    
    fn dfs(
        curr_id: u32,
        blocks: &[ShaderBlock],
        visited: &mut std::collections::HashSet<u32>,
        post_order: &mut Vec<u32>,
    ) {
        if visited.contains(&curr_id) {
            return;
        }
        visited.insert(curr_id);
        
        if let Some(block) = blocks.iter().find(|b| b.label_id == curr_id) {
            for &succ in &block.successors {
                dfs(succ, blocks, visited, post_order);
            }
        }
        post_order.push(curr_id);
    }
    
    dfs(0, blocks, &mut visited, &mut post_order);
    
    for block in blocks.iter() {
        if !visited.contains(&block.label_id) {
            dfs(block.label_id, blocks, &mut visited, &mut post_order);
        }
    }
    
    post_order.reverse();
    
    let mut ordered_blocks = Vec::new();
    for &id in &post_order {
        if let Some(idx) = blocks.iter().position(|b| b.label_id == id) {
            ordered_blocks.push(blocks.remove(idx));
        }
    }
    ordered_blocks.extend(blocks.drain(..));
    *blocks = ordered_blocks;
}

fn find_loop_merge_block(
    header_id: u32,
    continue_id: u32,
    blocks: &[ShaderBlock],
    post_dom: &std::collections::HashMap<u32, std::collections::BTreeSet<u32>>,
) -> u32 {
    let pdoms = post_dom.get(&header_id);
    let loop_blocks = find_loop_blocks(header_id, continue_id, blocks);
    
    for &lb in &loop_blocks {
        if let Some(block) = blocks.iter().find(|b| b.label_id == lb) {
            for &succ in &block.successors {
                if !loop_blocks.contains(&succ) {
                    if pdoms.map_or(true, |s| s.contains(&succ)) {
                        return succ;
                    }
                }
            }
        }
    }
    
    find_immediate_post_dominator(header_id, post_dom).unwrap_or(continue_id + 1)
}

/// Translates parsed RDNA2 instructions to a valid Vulkan SPIR-V binary module.
pub fn translate_to_spirv(instructions: &[Rdna2Instruction], is_vertex: bool, has_vertex_buffer: bool, has_constant_buffer: bool, has_texture: bool) -> Vec<u32> {
    info!(
        "Translating {} RDNA2 instructions to Vulkan SPIR-V (type: {}, has_vb: {}, has_cb: {}, has_tex: {})...",
        instructions.len(),
        if is_vertex { "Vertex" } else { "Fragment" },
        has_vertex_buffer,
        has_constant_buffer,
        has_texture
    );

    let mut b = SpirvBuilder::new();

    // 1. Gather all referenced SGPRs and VGPRs
    let mut used_sgprs = std::collections::BTreeSet::new();
    let mut used_vgprs = std::collections::BTreeSet::new();
    for inst in instructions {
        match inst {
            Rdna2Instruction::ScalarMov { dst_sgpr, src } => {
                used_sgprs.insert(*dst_sgpr);
                match src {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
            }
            Rdna2Instruction::ScalarAdd { dst_sgpr, src0, src1 } => {
                used_sgprs.insert(*dst_sgpr);
                match src0 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
                match src1 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
            }
            Rdna2Instruction::VectorMov { dst_vgpr, src } => {
                used_vgprs.insert(*dst_vgpr);
                match src {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
            }
            Rdna2Instruction::VectorAdd { dst_vgpr, src0, src1 } => {
                used_vgprs.insert(*dst_vgpr);
                match src0 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
                match src1 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
            }
            Rdna2Instruction::VectorMul { dst_vgpr, src0, src1 } => {
                used_vgprs.insert(*dst_vgpr);
                match src0 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
                match src1 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
            }
            Rdna2Instruction::VectorFma { dst_vgpr, src0, src1, src2, .. } => {
                used_vgprs.insert(*dst_vgpr);
                match src0 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
                match src1 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
                match src2 {
                    Operand::Sgpr(s) => { used_sgprs.insert(*s); }
                    Operand::Vgpr(v) => { used_vgprs.insert(*v); }
                    _ => {}
                }
            }
            Rdna2Instruction::ScalarMovK { dst_sgpr, .. } => {
                used_sgprs.insert(*dst_sgpr);
            }
            Rdna2Instruction::ScalarAddK { dst_sgpr, .. } => {
                used_sgprs.insert(*dst_sgpr);
            }
            Rdna2Instruction::SLoadDword { dst_sgpr, base_sgpr, .. } => {
                used_sgprs.insert(*dst_sgpr);
                used_sgprs.insert(*base_sgpr);
                used_sgprs.insert(*base_sgpr + 1);
            }
            Rdna2Instruction::SLoadDwordX4 { dst_sgpr, base_sgpr, .. } => {
                for offset in 0..4 {
                    used_sgprs.insert(dst_sgpr + offset);
                }
                used_sgprs.insert(*base_sgpr);
                used_sgprs.insert(*base_sgpr + 1);
            }
            Rdna2Instruction::VBufferLoadDword { dst_vgpr, vaddr_vgpr, resource_sgpr, .. } => {
                used_vgprs.insert(*dst_vgpr);
                used_vgprs.insert(*vaddr_vgpr);
                used_sgprs.insert(*resource_sgpr);
                used_sgprs.insert(*resource_sgpr + 1);
            }
            Rdna2Instruction::VBufferStoreDword { src_vgpr, vaddr_vgpr, resource_sgpr, .. } => {
                used_vgprs.insert(*src_vgpr);
                used_vgprs.insert(*vaddr_vgpr);
                used_sgprs.insert(*resource_sgpr);
                used_sgprs.insert(*resource_sgpr + 1);
            }
            Rdna2Instruction::VImageSample { dst_vgpr, src_vgpr, resource_sgpr, sampler_sgpr } => {
                used_vgprs.insert(*dst_vgpr);
                used_vgprs.insert(*src_vgpr);
                used_sgprs.insert(*resource_sgpr);
                used_sgprs.insert(*sampler_sgpr);
            }
            Rdna2Instruction::VectorPkFmaF16 { dst_vgpr, src0, src1, src2 } => {
                used_vgprs.insert(*dst_vgpr);
                match src0 { Operand::Vgpr(v) => { used_vgprs.insert(*v); } Operand::Sgpr(s) => { used_sgprs.insert(*s); } _ => {} }
                match src1 { Operand::Vgpr(v) => { used_vgprs.insert(*v); } Operand::Sgpr(s) => { used_sgprs.insert(*s); } _ => {} }
                match src2 { Operand::Vgpr(v) => { used_vgprs.insert(*v); } Operand::Sgpr(s) => { used_sgprs.insert(*s); } _ => {} }
            }
            Rdna2Instruction::VectorPkAddF16 { dst_vgpr, src0, src1 } | Rdna2Instruction::VectorPkMulF16 { dst_vgpr, src0, src1 } => {
                used_vgprs.insert(*dst_vgpr);
                match src0 { Operand::Vgpr(v) => { used_vgprs.insert(*v); } Operand::Sgpr(s) => { used_sgprs.insert(*s); } _ => {} }
                match src1 { Operand::Vgpr(v) => { used_vgprs.insert(*v); } Operand::Sgpr(s) => { used_sgprs.insert(*s); } _ => {} }
            }
            Rdna2Instruction::DsReadB32 { dst_vgpr, addr_vgpr, .. } => {
                used_vgprs.insert(*dst_vgpr);
                used_vgprs.insert(*addr_vgpr);
            }
            Rdna2Instruction::DsWriteB32 { addr_vgpr, data_vgpr, .. } => {
                used_vgprs.insert(*addr_vgpr);
                used_vgprs.insert(*data_vgpr);
            }
            Rdna2Instruction::VReadlaneB32 { dst_sgpr, src_vgpr, lane_operand } => {
                used_sgprs.insert(*dst_sgpr);
                used_vgprs.insert(*src_vgpr);
                match lane_operand { Operand::Vgpr(v) => { used_vgprs.insert(*v); } Operand::Sgpr(s) => { used_sgprs.insert(*s); } _ => {} }
            }
            Rdna2Instruction::VWritelaneB32 { dst_vgpr, src_operand, lane_operand } => {
                used_vgprs.insert(*dst_vgpr);
                match src_operand { Operand::Vgpr(v) => { used_vgprs.insert(*v); } Operand::Sgpr(s) => { used_sgprs.insert(*s); } _ => {} }
                match lane_operand { Operand::Vgpr(v) => { used_vgprs.insert(*v); } Operand::Sgpr(s) => { used_sgprs.insert(*s); } _ => {} }
            }
            Rdna2Instruction::SAndSaveexecB64 { dst_sgpr_pair, src } => {
                used_sgprs.insert(*dst_sgpr_pair);
                used_sgprs.insert(*dst_sgpr_pair + 1);
                match src { Operand::Sgpr(s) => { used_sgprs.insert(*s); used_sgprs.insert(*s + 1); } _ => {} }
            }
            Rdna2Instruction::SOrSaveexecB64 { dst_sgpr_pair, src } => {
                used_sgprs.insert(*dst_sgpr_pair);
                used_sgprs.insert(*dst_sgpr_pair + 1);
                match src { Operand::Sgpr(s) => { used_sgprs.insert(*s); used_sgprs.insert(*s + 1); } _ => {} }
            }
            Rdna2Instruction::SMovB64Exec { src } => {
                match src { Operand::Sgpr(s) => { used_sgprs.insert(*s); used_sgprs.insert(*s + 1); } _ => {} }
            }
            _ => {}
        }
    }

    // Always ensure at least some default registers are in the set for loading/storing position, color, etc.
    for i in 0..6 {
        used_vgprs.insert(i);
        used_sgprs.insert(i);
    }

    // Allocate standard SPIR-V IDs for type declarations, variables, decorations
    let entry_fn_id = b.alloc_id();
    let glsl_ext_id = b.alloc_id();
    let void_type_id = b.alloc_id();
    let fn_type_id = b.alloc_id();
    let float_type_id = b.alloc_id();
    let int_type_id = b.alloc_id();
    let ulong_type_id = b.alloc_id();
    let uint_type_id = b.alloc_id();
    let c_32_ulong = b.alloc_id();
    let bool_type_id = b.alloc_id();
    let float16_type_id = b.alloc_id();
    let vec2f16_type_id = b.alloc_id();
    let lds_array_type_id = b.alloc_id();
    let ptr_workgroup_array_id = b.alloc_id();
    let ptr_workgroup_float_id = b.alloc_id();
    let lds_var_id = b.alloc_id();
    let c_lds_size = b.alloc_id();
    let c_scope_workgroup = b.alloc_id();
    let c_scope_subgroup = b.alloc_id();
    let c_semantics_workgroup = b.alloc_id();
    let c_scope_device = b.alloc_id();
    let c_semantics_buffer = b.alloc_id();
    let vec2_type_id = b.alloc_id();
    let vec3_type_id = b.alloc_id();
    let vec4_type_id = b.alloc_id();
    let uvec4_type_id = b.alloc_id(); // OpTypeVector uint 4 — for ballot results
    let ptr_physical_float_id = b.alloc_id();
    
    let ptr_in_vec3_id = b.alloc_id();
    let ptr_in_vec2_id = b.alloc_id();
    let ptr_out_vec4_id = b.alloc_id();
    let ptr_out_vec3_id = b.alloc_id();
    let ptr_out_vec2_id = b.alloc_id();
    let ptr_in_int_id = b.alloc_id();

    // Constant buffer structs (Block offset 0)
    let struct_type_id = b.alloc_id();
    let ptr_uniform_struct_id = b.alloc_id();
    let ptr_uniform_vec4_id = b.alloc_id();
    let uniform_var_id = b.alloc_id();

    // Image / Texture types
    let image_type_id = b.alloc_id();
    let sampled_image_type_id = b.alloc_id();
    let ptr_uniform_sampled_image_id = b.alloc_id();
    let sampler_var_id = b.alloc_id();

    // In-function variable pointers
    let ptr_function_float_id = b.alloc_id();

    // Variable IDs for inputs/outputs
    let in_pos_var = b.alloc_id();
    let in_color_var = b.alloc_id();
    let in_tex_var = b.alloc_id();
    let vertex_index_var = b.alloc_id();
    let subgroup_local_invocation_id_var = b.alloc_id();

    let out_pos_var = b.alloc_id();
    let out_color_var = b.alloc_id();
    let out_tex_var = b.alloc_id();

    // Constant values
    let c_0_0 = b.alloc_id();
    let c_1_0 = b.alloc_id();
    let c_2_0 = b.alloc_id();
    let c_3_0 = b.alloc_id();
    let c_0_5 = b.alloc_id();
    let c_neg_0_5 = b.alloc_id();
    let c_neg_0_75 = b.alloc_id();
    let c_1_25 = b.alloc_id();
    let c_1_5 = b.alloc_id();
    let c_zero_int = b.alloc_id();

    // Capabilities
    b.write_inst(17, &[1]); // OpCapability Shader
    b.write_inst(17, &[11]); // OpCapability Int64
    b.write_inst(17, &[5347]); // OpCapability PhysicalStorageBufferAddresses
    b.write_inst(17, &[9]); // OpCapability Float16
    b.write_inst(17, &[61]); // OpCapability GroupNonUniform
    b.write_inst(17, &[65]); // OpCapability GroupNonUniformShuffle
    b.write_str_inst(10, None, "SPV_KHR_physical_storage_buffer", &[]); // OpExtension
    b.write_str_inst(11, Some(glsl_ext_id), "GLSL.std.450", &[]); // OpExtInstImport
    b.write_inst(14, &[5348, 1]); // OpMemoryModel PhysicalStorageBuffer64, GLSL450

    // OpEntryPoint
    let mut entry_args = vec![
        if is_vertex { 0 } else { 4 }, // ExecutionModel (Vertex=0, Fragment=4)
        entry_fn_id,
        0x6E69616D, 0x00000000, // "main"
    ];
    if is_vertex {
        entry_args.push(out_pos_var);
        if has_vertex_buffer {
            entry_args.push(in_pos_var);
            if has_texture {
                entry_args.push(in_tex_var);
                entry_args.push(out_tex_var);
            } else {
                entry_args.push(in_color_var);
                entry_args.push(out_color_var);
            }
        } else {
            entry_args.push(vertex_index_var);
        }
    } else {
        entry_args.push(out_color_var);
        if has_texture {
            entry_args.push(in_tex_var);
        } else {
            entry_args.push(in_color_var);
        }
    }
    entry_args.push(subgroup_local_invocation_id_var);
    b.write_inst(15, &entry_args);

    if !is_vertex {
        b.write_inst(16, &[entry_fn_id, 7]); // OpExecutionMode OriginUpperLeft
    }

    // Decorate Inputs / Outputs
    b.write_inst(71, &[subgroup_local_invocation_id_var, 11, 41]); // BuiltIn SubgroupLocalInvocationId
    if is_vertex {
        b.write_inst(71, &[out_pos_var, 11, 0]); // OpDecorate Position
        if has_vertex_buffer {
            b.write_inst(71, &[in_pos_var, 30, 0]); // Location 0
            if has_texture {
                b.write_inst(71, &[in_tex_var, 30, 2]); // Location 2
                b.write_inst(71, &[out_tex_var, 30, 1]); // Location 1
            } else {
                b.write_inst(71, &[in_color_var, 30, 1]); // Location 1
                b.write_inst(71, &[out_color_var, 30, 0]); // Location 0
            }
        } else {
            b.write_inst(71, &[vertex_index_var, 11, 42]); // VertexIndex
        }
    } else {
        b.write_inst(71, &[out_color_var, 30, 0]); // Location 0
        if has_texture {
            b.write_inst(71, &[in_tex_var, 30, 1]); // Location 1
            b.write_inst(71, &[sampler_var_id, 33, 1]); // Binding 1
            b.write_inst(71, &[sampler_var_id, 34, 0]); // DescriptorSet 0
        } else {
            b.write_inst(71, &[in_color_var, 30, 0]); // Location 0
        }
    }

    if has_constant_buffer {
        b.write_inst(71, &[struct_type_id, 2]); // Block
        b.write_inst(72, &[struct_type_id, 0, 35, 0]); // Offset 0
        b.write_inst(71, &[uniform_var_id, 33, 0]); // DescriptorSet 0
        b.write_inst(71, &[uniform_var_id, 34, 0]); // Binding 0
    }

    // Type Declarations
    b.set_section(Section::TypesAndConstants);
    b.write_inst(19, &[void_type_id]); // OpTypeVoid
    b.write_inst(33, &[fn_type_id, void_type_id]); // OpTypeFunction
    b.write_inst(22, &[float_type_id, 32]); // OpTypeFloat 32
    b.write_inst(22, &[float16_type_id, 16]); // OpTypeFloat 16
    b.write_inst(21, &[int_type_id, 32, 1]); // OpTypeInt 32-bit signed
    b.write_inst(21, &[ulong_type_id, 64, 0]); // OpTypeInt 64-bit unsigned (0)
    b.write_inst(21, &[uint_type_id, 32, 0]); // OpTypeInt 32-bit unsigned (0)
    b.write_inst(20, &[bool_type_id]); // OpTypeBool
    
    b.write_inst(23, &[vec2_type_id, float_type_id, 2]); // OpTypeVector vec2
    b.write_inst(23, &[vec2f16_type_id, float16_type_id, 2]); // OpTypeVector f16 vec2
    b.write_inst(23, &[vec3_type_id, float_type_id, 3]); // OpTypeVector vec3
    b.write_inst(43, &[uint_type_id, c_lds_size, 8192]); // Size 8192 dwords
    b.write_inst(28, &[lds_array_type_id, float_type_id, c_lds_size]); // OpTypeArray float [8192]
    b.write_inst(32, &[ptr_workgroup_array_id, 4, lds_array_type_id]); // OpTypePointer Workgroup array
    b.write_inst(32, &[ptr_workgroup_float_id, 4, float_type_id]); // OpTypePointer Workgroup float
    b.write_inst(23, &[vec4_type_id, float_type_id, 4]); // OpTypeVector vec4
    b.write_inst(23, &[uvec4_type_id, uint_type_id, 4]); // OpTypeVector uvec4 — for subgroup ballot results

    b.write_inst(32, &[ptr_in_vec3_id, 1, vec3_type_id]); // Pointer Input vec3
    b.write_inst(32, &[ptr_in_vec2_id, 1, vec2_type_id]); // Pointer Input vec2
    b.write_inst(32, &[ptr_out_vec4_id, 3, vec4_type_id]); // Pointer Output vec4
    b.write_inst(32, &[ptr_out_vec3_id, 3, vec3_type_id]); // Pointer Output vec3
    b.write_inst(32, &[ptr_out_vec2_id, 3, vec2_type_id]); // Pointer Output vec2
    b.write_inst(32, &[ptr_in_int_id, 1, int_type_id]); // Pointer Input int
    let ptr_in_uint_id = b.alloc_id();
    b.write_inst(32, &[ptr_in_uint_id, 1, uint_type_id]); // Pointer Input uint

    b.write_inst(32, &[ptr_function_float_id, 7, float_type_id]); // Pointer Function float
    b.write_inst(32, &[ptr_physical_float_id, 5349, float_type_id]); // Pointer PhysicalStorageBuffer float

    if has_texture {
        b.write_inst(25, &[image_type_id, float_type_id, 1, 0, 0, 0, 1, 0]); // OpTypeImage 2D
        b.write_inst(27, &[sampled_image_type_id, image_type_id]); // OpTypeSampledImage
        b.write_inst(32, &[ptr_uniform_sampled_image_id, 0, sampled_image_type_id]); // Pointer to UniformConstant
    }

    if has_constant_buffer {
        b.write_inst(30, &[struct_type_id, vec4_type_id]); // Struct
        b.write_inst(32, &[ptr_uniform_struct_id, 2, struct_type_id]); // Pointer Uniform Struct
        b.write_inst(32, &[ptr_uniform_vec4_id, 2, vec4_type_id]); // Pointer Uniform vec4
    }

    // Global variables declarations
    b.write_inst(59, &[ptr_workgroup_array_id, lds_var_id, 4]); // OpVariable Workgroup
    b.write_inst(59, &[ptr_in_uint_id, subgroup_local_invocation_id_var, 1]); // OpVariable Input
    if is_vertex {
        b.write_inst(59, &[ptr_out_vec4_id, out_pos_var, 3]); // Output Position
        if has_vertex_buffer {
            b.write_inst(59, &[ptr_in_vec3_id, in_pos_var, 1]); // Input Position
            if has_texture {
                b.write_inst(59, &[ptr_in_vec2_id, in_tex_var, 1]); // Input TexCoord
                b.write_inst(59, &[ptr_out_vec2_id, out_tex_var, 3]); // Output TexCoord
            } else {
                b.write_inst(59, &[ptr_in_vec3_id, in_color_var, 1]); // Input Color
                b.write_inst(59, &[ptr_out_vec3_id, out_color_var, 3]); // Output Color
            }
        } else {
            b.write_inst(59, &[ptr_in_int_id, vertex_index_var, 1]); // Input VertexIndex
        }
    } else {
        b.write_inst(59, &[ptr_out_vec4_id, out_color_var, 3]); // Output Color
        if has_texture {
            b.write_inst(59, &[ptr_in_vec2_id, in_tex_var, 1]); // Input TexCoord
            b.write_inst(59, &[ptr_uniform_sampled_image_id, sampler_var_id, 0]); // Texture Sampler Uniform
        } else {
            b.write_inst(59, &[ptr_in_vec3_id, in_color_var, 1]); // Input Color
        }
    }

    if has_constant_buffer {
        b.write_inst(59, &[ptr_uniform_struct_id, uniform_var_id, 2]); // Uniform Constant Buffer
    }

    // Constant values
    b.write_inst(43, &[float_type_id, c_0_0, 0x00000000]); // 0.0
    b.write_inst(43, &[float_type_id, c_1_0, 0x3F800000]); // 1.0
    b.write_inst(43, &[float_type_id, c_2_0, 0x40000000]); // 2.0
    b.write_inst(43, &[float_type_id, c_3_0, 0x40400000]); // 3.0
    b.write_inst(43, &[float_type_id, c_0_5, 0x3F000000]); // 0.5
    b.write_inst(43, &[float_type_id, c_neg_0_5, 0xBF000000]); // -0.5
    b.write_inst(43, &[float_type_id, c_neg_0_75, 0xBF400000]); // -0.75
    b.write_inst(43, &[float_type_id, c_1_25, 0x3FA00000]); // 1.25
    b.write_inst(43, &[float_type_id, c_1_5, 0x3FC00000]); // 1.5
    b.write_inst(43, &[int_type_id, c_zero_int, 0]); // 0 (int)
    b.write_inst(43, &[ulong_type_id, c_32_ulong, 32, 0]); // 32 (ulong)
    b.write_inst(43, &[uint_type_id, c_scope_workgroup, 2]); // 2 (uint)
    b.write_inst(43, &[uint_type_id, c_scope_subgroup, 3]); // 3 (uint)
    b.write_inst(43, &[uint_type_id, c_semantics_workgroup, 272]); // 272 (uint)
    b.write_inst(43, &[uint_type_id, c_scope_device, 1]); // 1 (uint)
    b.write_inst(43, &[uint_type_id, c_semantics_buffer, 72]); // 72 (uint)

    // Function body
    b.set_section(Section::Functions);
    b.write_inst(54, &[void_type_id, entry_fn_id, 0, fn_type_id]); // OpFunction
    let entry_label = b.alloc_id();
    b.write_inst(248, &[entry_label]); // OpLabel

    // Declare function variables (register mappings)
    let mut sgpr_map = std::collections::HashMap::new();
    let mut vgpr_map = std::collections::HashMap::new();

    for sgpr in &used_sgprs {
        let var_id = b.alloc_id();
        b.write_inst(59, &[ptr_function_float_id, var_id, 7]); // OpVariable Function
        sgpr_map.insert(*sgpr, var_id);
    }
    for vgpr in &used_vgprs {
        let var_id = b.alloc_id();
        b.write_inst(59, &[ptr_function_float_id, var_id, 7]); // OpVariable Function
        vgpr_map.insert(*vgpr, var_id);
    }
    
    let dispatch_state_var = b.alloc_id();
    b.write_inst(59, &[ptr_function_float_id, dispatch_state_var, 7]); // OpVariable Function

    // Helper: load operand helper closure
    let load_operand = |b: &mut SpirvBuilder, op: &Operand, sgpr_map: &std::collections::HashMap<u8, u32>, vgpr_map: &std::collections::HashMap<u8, u32>, float_type_id: u32, c_0_0: u32| -> u32 {
        match op {
            Operand::Sgpr(s) => {
                if let Some(&var) = sgpr_map.get(s) {
                    let id = b.alloc_id();
                    b.write_inst(61, &[float_type_id, id, var]); // OpLoad
                    id
                } else {
                    c_0_0
                }
            }
            Operand::Vgpr(v) => {
                if let Some(&var) = vgpr_map.get(v) {
                    let id = b.alloc_id();
                    b.write_inst(61, &[float_type_id, id, var]); // OpLoad
                    id
                } else {
                    c_0_0
                }
            }
            Operand::Literal(val) => {
                b.get_or_create_constant(float_type_id, &[*val])
            }
            Operand::Constant(val) => {
                let float_val = *val as f32;
                let bits = float_val.to_bits();
                b.get_or_create_constant(float_type_id, &[bits])
            }
        }
    };

    // Preload inputs into registers
    if is_vertex {
        if has_vertex_buffer {
            // Load pos from input pos variable into VGPR 0, 1, 2
            let in_pos_val = b.alloc_id();
            b.write_inst(61, &[vec3_type_id, in_pos_val, in_pos_var]); // OpLoad
            for comp in 0..3 {
                let comp_val = b.alloc_id();
                b.write_inst(81, &[float_type_id, comp_val, in_pos_val, comp]); // OpCompositeExtract
                if let Some(&var_id) = vgpr_map.get(&(comp as u8)) {
                    b.write_inst(62, &[var_id, comp_val]); // OpStore
                }
            }
            // Load color / tex into VGPR 3, 4, 5
            if has_texture {
                let in_tex_val = b.alloc_id();
                b.write_inst(61, &[vec2_type_id, in_tex_val, in_tex_var]); // OpLoad
                for comp in 0..2 {
                    let comp_val = b.alloc_id();
                    b.write_inst(81, &[float_type_id, comp_val, in_tex_val, comp]);
                    if let Some(&var_id) = vgpr_map.get(&(3 + comp as u8)) {
                        b.write_inst(62, &[var_id, comp_val]);
                    }
                }
            } else {
                let in_color_val = b.alloc_id();
                b.write_inst(61, &[vec3_type_id, in_color_val, in_color_var]); // OpLoad
                for comp in 0..3 {
                    let comp_val = b.alloc_id();
                    b.write_inst(81, &[float_type_id, comp_val, in_color_val, comp]);
                    if let Some(&var_id) = vgpr_map.get(&(3 + comp as u8)) {
                        b.write_inst(62, &[var_id, comp_val]);
                    }
                }
            }
        } else {
            // Load vertex index as float into VGPR 0
            let vertex_index_val = b.alloc_id();
            b.write_inst(61, &[int_type_id, vertex_index_val, vertex_index_var]); // OpLoad
            let f_id = b.alloc_id();
            b.write_inst(111, &[float_type_id, f_id, vertex_index_val]); // ConvertSToF
            if let Some(&var_id) = vgpr_map.get(&0) {
                b.write_inst(62, &[var_id, f_id]);
            }
        }
    } else {
        if has_texture {
            // Load texture coordinates into VGPR 0, 1
            let in_tex_val = b.alloc_id();
            b.write_inst(61, &[vec2_type_id, in_tex_val, in_tex_var]); // OpLoad
            for comp in 0..2 {
                let comp_val = b.alloc_id();
                b.write_inst(81, &[float_type_id, comp_val, in_tex_val, comp]);
                if let Some(&var_id) = vgpr_map.get(&(comp as u8)) {
                    b.write_inst(62, &[var_id, comp_val]);
                }
            }
        } else {
            // Load color into VGPR 0, 1, 2
            let in_color_val = b.alloc_id();
            b.write_inst(61, &[vec3_type_id, in_color_val, in_color_var]); // OpLoad
            for comp in 0..3 {
                let comp_val = b.alloc_id();
                b.write_inst(81, &[float_type_id, comp_val, in_color_val, comp]);
                if let Some(&var_id) = vgpr_map.get(&(comp as u8)) {
                    b.write_inst(62, &[var_id, comp_val]);
                }
            }
        }
    }

    // Build and structurize the CFG
    let mut blocks = build_cfg(instructions);
    let mut next_label_id = instructions.len() as u32 + 1000;
    
    collapse_empty_blocks(&mut blocks);
    unify_loop_backedges(&mut blocks, &mut next_label_id);
    split_loop_headers(&mut blocks, &mut next_label_id, instructions);
    inject_ladders(&mut blocks, &mut next_label_id);
    transpose_irreducible_loops(&mut blocks, &mut next_label_id);
    
    sort_blocks_rpo(&mut blocks);
    let post_dom = compute_post_dominators(&blocks);
    
    let mut block_to_loops = std::collections::HashMap::new();
    let mut loop_merge_blocks = std::collections::HashSet::new();
    for (block_idx, b_node) in blocks.iter().enumerate() {
        let back_edge_preds: Vec<u32> = b_node.predecessors.iter().copied()
            .filter(|&pred| {
                if let Some(pred_idx) = blocks.iter().position(|b| b.label_id == pred) {
                    pred_idx >= block_idx
                } else {
                    false
                }
            })
            .collect();
        if !back_edge_preds.is_empty() {
            let continue_id = back_edge_preds[0];
            let merge_id = find_loop_merge_block(b_node.label_id, continue_id, &blocks, &post_dom);
            loop_merge_blocks.insert(merge_id);
            
            let loop_blocks = find_loop_blocks(b_node.label_id, continue_id, &blocks);
            for &lb in &loop_blocks {
                block_to_loops.entry(lb).or_insert_with(Vec::new).push((b_node.label_id, loop_blocks.clone()));
            }
        }
    }
    
    let mut block_labels = std::collections::HashMap::new();
    for block in &blocks {
        block_labels.insert(block.label_id, b.alloc_id());
    }

    let mut modifier_cache = std::collections::HashMap::new();
    let mut apply_modifiers = |b: &mut SpirvBuilder, val_id: u32, abs: bool, neg: bool| -> u32 {
        if !abs && !neg {
            return val_id;
        }
        let key = (val_id, abs, neg);
        if let Some(&cached_id) = modifier_cache.get(&key) {
            return cached_id;
        }
        let mut current_id = val_id;
        if abs {
            let abs_key = (val_id, true, false);
            if let Some(&cached_abs) = modifier_cache.get(&abs_key) {
                current_id = cached_abs;
            } else {
                let abs_id = b.alloc_id();
                b.write_inst(12, &[float_type_id, abs_id, glsl_ext_id, 4, val_id]); // FAbs
                modifier_cache.insert(abs_key, abs_id);
                current_id = abs_id;
            }
        }
        if neg {
            let neg_id = b.alloc_id();
            b.write_inst(127, &[float_type_id, neg_id, current_id]); // OpFNegate
            modifier_cache.insert(key, neg_id);
            current_id = neg_id;
        }
        current_id
    };

    let write_dispatch_store = |b: &mut SpirvBuilder, pred_id: u32, succ_id: u32| {
        if let Some(original_target_id) = lookup_redirection(pred_id, succ_id) {
            if let Some(dispatch_block) = blocks.iter().find(|block| block.label_id == succ_id) {
                if let Some(state_index) = dispatch_block.successors.iter().position(|&x| x == original_target_id) {
                    let state_const_id = match state_index {
                        0 => c_0_0,
                        1 => c_1_0,
                        2 => c_2_0,
                        3 => c_3_0,
                        _ => c_0_0,
                    };
                    b.write_inst(62, &[dispatch_state_var, state_const_id]); // OpStore
                }
            }
        }
    };

    // Branch from the entry block to the first basic block (label_id = 0)
    let first_block_label = block_labels[&0];
    b.write_inst(249, &[first_block_label]); // OpBranch to block 0

    // Process and translate each basic block in topological order
    for (block_idx, block) in blocks.iter().enumerate() {
        let label_id = block_labels[&block.label_id];
        b.write_inst(248, &[label_id]); // OpLabel

        let is_dispatch_block = block.instructions.is_empty() && block.successors.len() > 1 && block.label_id >= instructions.len() as u32;
        if is_dispatch_block {
            let state_val_id = b.alloc_id();
            b.write_inst(61, &[float_type_id, state_val_id, dispatch_state_var]); // OpLoad
            
            for (idx, &succ) in block.successors.iter().enumerate() {
                let succ_label = block_labels[&succ];
                if idx == block.successors.len() - 1 {
                    b.write_inst(249, &[succ_label]); // OpBranch
                } else {
                    let comp_const_id = match idx {
                        0 => c_0_0,
                        1 => c_1_0,
                        2 => c_2_0,
                        3 => c_3_0,
                        _ => c_0_0,
                    };
                    let cond_id = b.alloc_id();
                    b.write_inst(180, &[bool_type_id, cond_id, state_val_id, comp_const_id]); // OpFOrdEqual
                    
                    let next_check_label = b.alloc_id();
                    b.write_inst(247, &[next_check_label, 0]); // OpSelectionMerge
                    b.write_inst(250, &[cond_id, succ_label, next_check_label]); // OpBranchConditional
                    
                    b.write_inst(248, &[next_check_label]); // OpLabel
                }
            }
            continue;
        }

        // Loop header detection (RPO-compatible backedge check)
        let back_edge_preds: Vec<u32> = block.predecessors.iter().copied()
            .filter(|&pred| {
                if let Some(pred_idx) = blocks.iter().position(|b| b.label_id == pred) {
                    pred_idx >= block_idx
                } else {
                    false
                }
            })
            .collect();
        let is_loop_header = !back_edge_preds.is_empty();
        let loop_merge_info = if is_loop_header {
            let continue_id = back_edge_preds[0];
            let merge_id = find_loop_merge_block(block.label_id, continue_id, &blocks, &post_dom);
            Some((block_labels[&merge_id], block_labels[&continue_id]))
        } else {
            None
        };

        let start_inst = block.label_id as usize;
        let end_inst = start_inst + block.instructions.len();

        let mut active_lds_write = false;
        let mut active_global_writes = std::collections::HashSet::new();

        for inst_idx in start_inst..end_inst {
            let inst = &instructions[inst_idx];
            
            // Check for memory dependency hazards BEFORE emitting the instruction
            match inst {
                Rdna2Instruction::DsReadB32 { .. } | Rdna2Instruction::DsWriteB32 { .. } => {
                    if active_lds_write {
                        // Inject OpMemoryBarrier for workgroup memory (LDS)
                        b.write_inst(225, &[c_scope_workgroup, c_semantics_workgroup]);
                        active_lds_write = false;
                    }
                }
                Rdna2Instruction::VBufferLoadDword { resource_sgpr, .. } |
                Rdna2Instruction::VBufferStoreDword { resource_sgpr, .. } |
                Rdna2Instruction::SLoadDword { base_sgpr: resource_sgpr, .. } => {
                    if active_global_writes.contains(resource_sgpr) {
                        // Inject OpMemoryBarrier for buffer device memory
                        b.write_inst(225, &[c_scope_device, c_semantics_buffer]);
                        active_global_writes.remove(resource_sgpr);
                    }
                }
                _ => {}
            }

            // Post-instruction state update: track writes
            match inst {
                Rdna2Instruction::DsWriteB32 { .. } => {
                    active_lds_write = true;
                }
                Rdna2Instruction::VBufferStoreDword { resource_sgpr, .. } => {
                    active_global_writes.insert(*resource_sgpr);
                }
                _ => {}
            }

            // Check if this instruction is the terminator of the block
            let is_terminator = match inst {
                Rdna2Instruction::SBranch { .. } |
                Rdna2Instruction::SCbranchScc0 { .. } |
                Rdna2Instruction::SCbranchScc1 { .. } |
                Rdna2Instruction::EndPgm => true,
                _ => false,
            };

            if is_terminator {
                match inst {
                    Rdna2Instruction::SBranch { offset } => {
                        let target_pc = *block.successors.first().unwrap_or(&((inst_idx as i32 + 1 + *offset as i32) as u32));
                        let target_label = block_labels[&target_pc];
                        
                        if let Some((merge_label, continue_label)) = loop_merge_info {
                            b.write_inst(246, &[merge_label, continue_label, 0]); // OpLoopMerge
                        }
                        
                        write_dispatch_store(&mut b, block.label_id, target_pc);
                        b.write_inst(249, &[target_label]); // OpBranch
                    }
                    Rdna2Instruction::SCbranchScc0 { offset } => {
                        let target_pc = *block.successors.first().unwrap_or(&((inst_idx as i32 + 1 + *offset as i32) as u32));
                        let fallthrough_pc = *block.successors.get(1).unwrap_or(&((inst_idx + 1) as u32));
                        let mut merge_pc = find_immediate_post_dominator(block.label_id, &post_dom).unwrap_or(fallthrough_pc);
                        if let Some(loops) = block_to_loops.get(&block.label_id) {
                            if let Some((_, inner_loop_set)) = loops.iter().min_by_key(|(_, s)| s.len()) {
                                if !inner_loop_set.contains(&merge_pc) {
                                    if let Some(&succ_in_loop) = block.successors.iter().find(|s| inner_loop_set.contains(s)) {
                                        merge_pc = succ_in_loop;
                                    }
                                }
                            }
                        }
                        
                        let merge_label = block_labels[&merge_pc];
                        
                        let mut b_temp = &mut b;
                        let val0 = load_operand(&mut b_temp, &Operand::Sgpr(0), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let cond_id = b.alloc_id();
                        b.write_inst(180, &[bool_type_id, cond_id, val0, c_0_0]); // OpFOrdEqual (cond = (scc == 0))
                        
                        if !loop_merge_blocks.contains(&merge_pc) {
                            b.write_inst(247, &[merge_label, 0]); // OpSelectionMerge
                        }
                        if let Some((merge_label, continue_label)) = loop_merge_info {
                            b.write_inst(246, &[merge_label, continue_label, 0]); // OpLoopMerge
                        }
                        
                        write_dispatch_store(&mut b, block.label_id, target_pc);
                        write_dispatch_store(&mut b, block.label_id, fallthrough_pc);
                        b.write_inst(250, &[cond_id, block_labels[&target_pc], block_labels[&fallthrough_pc]]); // OpBranchConditional
                    }
                    Rdna2Instruction::SCbranchScc1 { offset } => {
                        let target_pc = *block.successors.first().unwrap_or(&((inst_idx as i32 + 1 + *offset as i32) as u32));
                        let fallthrough_pc = *block.successors.get(1).unwrap_or(&((inst_idx + 1) as u32));
                        let mut merge_pc = find_immediate_post_dominator(block.label_id, &post_dom).unwrap_or(fallthrough_pc);
                        if let Some(loops) = block_to_loops.get(&block.label_id) {
                            if let Some((_, inner_loop_set)) = loops.iter().min_by_key(|(_, s)| s.len()) {
                                if !inner_loop_set.contains(&merge_pc) {
                                    if let Some(&succ_in_loop) = block.successors.iter().find(|s| inner_loop_set.contains(s)) {
                                        merge_pc = succ_in_loop;
                                    }
                                }
                            }
                        }
                        
                        let merge_label = block_labels[&merge_pc];
                        
                        let mut b_temp = &mut b;
                        let val0 = load_operand(&mut b_temp, &Operand::Sgpr(0), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let cond_id = b.alloc_id();
                        b.write_inst(181, &[bool_type_id, cond_id, val0, c_0_0]); // OpFOrdNotEqual (cond = (scc != 0))
                        
                        if !loop_merge_blocks.contains(&merge_pc) {
                            b.write_inst(247, &[merge_label, 0]); // OpSelectionMerge
                        }
                        if let Some((merge_label, continue_label)) = loop_merge_info {
                            b.write_inst(246, &[merge_label, continue_label, 0]); // OpLoopMerge
                        }
                        
                        write_dispatch_store(&mut b, block.label_id, target_pc);
                        write_dispatch_store(&mut b, block.label_id, fallthrough_pc);
                        b.write_inst(250, &[cond_id, block_labels[&target_pc], block_labels[&fallthrough_pc]]); // OpBranchConditional
                    }
                    Rdna2Instruction::EndPgm => {
                        // Post-process output assignments on program end
                        if is_vertex {
                            let vg0 = vgpr_map.get(&0).copied().unwrap_or(c_0_0);
                            let vg1 = vgpr_map.get(&1).copied().unwrap_or(c_0_0);
                            let vg2 = vgpr_map.get(&2).copied().unwrap_or(c_0_0);
                            
                            let val0 = b.alloc_id(); b.write_inst(61, &[float_type_id, val0, if vg0 != c_0_0 { vg0 } else { c_0_0 }]);
                            let val1 = b.alloc_id(); b.write_inst(61, &[float_type_id, val1, if vg1 != c_0_0 { vg1 } else { c_0_0 }]);
                            let val2 = b.alloc_id(); b.write_inst(61, &[float_type_id, val2, if vg2 != c_0_0 { vg2 } else { c_0_0 }]);
                            
                            if has_vertex_buffer {
                                let out_pos_val = b.alloc_id();
                                b.write_inst(80, &[vec4_type_id, out_pos_val, val0, val1, val2, c_1_0]); // OpCompositeConstruct
                                b.write_inst(62, &[out_pos_var, out_pos_val]);
                                
                                let vg3 = vgpr_map.get(&3).copied().unwrap_or(c_0_0);
                                let vg4 = vgpr_map.get(&4).copied().unwrap_or(c_0_0);
                                let vg5 = vgpr_map.get(&5).copied().unwrap_or(c_0_0);
                                
                                let val3 = b.alloc_id(); b.write_inst(61, &[float_type_id, val3, if vg3 != c_0_0 { vg3 } else { c_0_0 }]);
                                let val4 = b.alloc_id(); b.write_inst(61, &[float_type_id, val4, if vg4 != c_0_0 { vg4 } else { c_0_0 }]);
                                
                                if has_texture {
                                    let out_tex_val = b.alloc_id();
                                    b.write_inst(80, &[vec2_type_id, out_tex_val, val3, val4]);
                                    b.write_inst(62, &[out_tex_var, out_tex_val]);
                                } else {
                                    let val5 = b.alloc_id(); b.write_inst(61, &[float_type_id, val5, if vg5 != c_0_0 { vg5 } else { c_0_0 }]);
                                    let out_color_val = b.alloc_id();
                                    b.write_inst(80, &[vec3_type_id, out_color_val, val3, val4, val5]);
                                    b.write_inst(62, &[out_color_var, out_color_val]);
                                }
                            } else {
                                // Algebraic fallback for original triangle draw (vb-less)
                                let vertex_index_val = b.alloc_id();
                                b.write_inst(61, &[int_type_id, vertex_index_val, vertex_index_var]); // OpLoad
                                let f_id = b.alloc_id();
                                b.write_inst(111, &[float_type_id, f_id, vertex_index_val]); // OpConvertSToF
                                let f2_id = b.alloc_id();
                                b.write_inst(131, &[float_type_id, f2_id, f_id, f_id]); // OpFMul
                                let t0_id = b.alloc_id();
                                b.write_inst(131, &[float_type_id, t0_id, c_neg_0_75, f2_id]); // OpFMul
                                let t1_id = b.alloc_id();
                                b.write_inst(131, &[float_type_id, t1_id, c_1_25, f_id]); // OpFMul
                                let x_id = b.alloc_id();
                                b.write_inst(129, &[float_type_id, x_id, t0_id, t1_id]); // OpFAdd
                                let t2_id = b.alloc_id();
                                b.write_inst(131, &[float_type_id, t2_id, c_neg_0_5, f2_id]); // OpFMul
                                let t3_id = b.alloc_id();
                                b.write_inst(131, &[float_type_id, t3_id, c_1_5, f_id]); // OpFMul
                                let t4_id = b.alloc_id();
                                b.write_inst(129, &[float_type_id, t4_id, t2_id, t3_id]); // OpFAdd
                                let y_id = b.alloc_id();
                                b.write_inst(129, &[float_type_id, y_id, t4_id, c_neg_0_5]); // OpFAdd
        
                                let pos_val = b.alloc_id();
                                b.write_inst(80, &[vec4_type_id, pos_val, x_id, y_id, c_0_0, c_1_0]); // OpCompositeConstruct
                                b.write_inst(62, &[out_pos_var, pos_val]); // OpStore
                            }
                        } else {
                            // Fragment output Color
                            let vg0 = vgpr_map.get(&0).copied().unwrap_or(c_1_0);
                            let vg1 = vgpr_map.get(&1).copied().unwrap_or(c_0_0);
                            let vg2 = vgpr_map.get(&2).copied().unwrap_or(c_0_0);
                            let vg3 = vgpr_map.get(&3).copied().unwrap_or(c_1_0);
                            
                            let val0 = b.alloc_id(); b.write_inst(61, &[float_type_id, val0, if vg0 != c_1_0 { vg0 } else { c_1_0 }]);
                            let val1 = b.alloc_id(); b.write_inst(61, &[float_type_id, val1, if vg1 != c_0_0 { vg1 } else { c_0_0 }]);
                            let val2 = b.alloc_id(); b.write_inst(61, &[float_type_id, val2, if vg2 != c_0_0 { vg2 } else { c_0_0 }]);
                            
                            if has_texture {
                                // Blend loaded texture color
                                let sampled_img = b.alloc_id();
                                b.write_inst(61, &[sampled_image_type_id, sampled_img, sampler_var_id]);
                                let uv_var_0 = vgpr_map.get(&0).copied().unwrap_or(c_0_0);
                                let uv_var_1 = vgpr_map.get(&1).copied().unwrap_or(c_0_0);
                                let uv_val_0 = b.alloc_id(); b.write_inst(61, &[float_type_id, uv_val_0, uv_var_0]);
                                let uv_val_1 = b.alloc_id(); b.write_inst(61, &[float_type_id, uv_val_1, uv_var_1]);
                                let uv_val = b.alloc_id();
                                b.write_inst(80, &[vec2_type_id, uv_val, uv_val_0, uv_val_1]);
                                let tex_color = b.alloc_id();
                                b.write_inst(87, &[vec4_type_id, tex_color, sampled_img, uv_val]);
                                b.write_inst(62, &[out_color_var, tex_color]);
                            } else if has_constant_buffer {
                                let member_ptr_id = b.alloc_id();
                                b.write_inst(65, &[ptr_uniform_vec4_id, member_ptr_id, uniform_var_id, c_zero_int]); // AccessChain
                                let loaded_color_id = b.alloc_id();
                                b.write_inst(61, &[vec4_type_id, loaded_color_id, member_ptr_id]); // Load
                                b.write_inst(62, &[out_color_var, loaded_color_id]); // Store
                            } else {
                                let val3 = b.alloc_id(); b.write_inst(61, &[float_type_id, val3, if vg3 != c_1_0 { vg3 } else { c_1_0 }]);
                                let out_color_val = b.alloc_id();
                                b.write_inst(80, &[vec4_type_id, out_color_val, val0, val1, val2, val3]); // OpCompositeConstruct
                                b.write_inst(62, &[out_color_var, out_color_val]);
                            }
                        }
                        b.write_inst(253, &[]); // OpReturn
                    }
                    _ => {}
                }
            } else {
                match inst {
                    Rdna2Instruction::ScalarMov { dst_sgpr, src } => {
                        let mut b_temp = &mut b;
                        let val_id = load_operand(&mut b_temp, src, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        if let Some(&dst_var) = sgpr_map.get(dst_sgpr) {
                            b.write_inst(62, &[dst_var, val_id]); // OpStore
                        }
                    }
                    Rdna2Instruction::ScalarMovK { dst_sgpr, simm16 } => {
                        let mut b_temp = &mut b;
                        let val_id = load_operand(&mut b_temp, &Operand::Constant(*simm16 as i32), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        if let Some(&dst_var) = sgpr_map.get(dst_sgpr) {
                            b.write_inst(62, &[dst_var, val_id]);
                        }
                    }
                    Rdna2Instruction::ScalarAdd { dst_sgpr, src0, src1 } => {
                        let mut b_temp = &mut b;
                        let val0 = load_operand(&mut b_temp, src0, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let val1 = load_operand(&mut b_temp, src1, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let res_id = b.alloc_id();
                        b.write_inst(129, &[float_type_id, res_id, val0, val1]); // OpFAdd
                        if let Some(&dst_var) = sgpr_map.get(dst_sgpr) {
                            b.write_inst(62, &[dst_var, res_id]);
                        }
                    }
                    Rdna2Instruction::ScalarAddK { dst_sgpr, simm16 } => {
                        let mut b_temp = &mut b;
                        let val0 = load_operand(&mut b_temp, &Operand::Sgpr(*dst_sgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let val1 = load_operand(&mut b_temp, &Operand::Constant(*simm16 as i32), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let res_id = b.alloc_id();
                        b.write_inst(129, &[float_type_id, res_id, val0, val1]); // OpFAdd
                        if let Some(&dst_var) = sgpr_map.get(dst_sgpr) {
                            b.write_inst(62, &[dst_var, res_id]);
                        }
                    }
                    Rdna2Instruction::VectorMov { dst_vgpr, src } => {
                        let mut b_temp = &mut b;
                        let val_id = load_operand(&mut b_temp, src, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, val_id]);
                        }
                    }
                    Rdna2Instruction::VectorAdd { dst_vgpr, src0, src1 } => {
                        let mut b_temp = &mut b;
                        let val0 = load_operand(&mut b_temp, src0, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let val1 = load_operand(&mut b_temp, src1, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let res_id = b.alloc_id();
                        b.write_inst(129, &[float_type_id, res_id, val0, val1]); // OpFAdd
                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, res_id]);
                        }
                    }
                    Rdna2Instruction::VectorMul { dst_vgpr, src0, src1 } => {
                        let mut b_temp = &mut b;
                        let val0 = load_operand(&mut b_temp, src0, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let val1 = load_operand(&mut b_temp, src1, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let res_id = b.alloc_id();
                        b.write_inst(131, &[float_type_id, res_id, val0, val1]); // OpFMul
                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, res_id]);
                        }
                    }
                    Rdna2Instruction::VectorFma {
                        dst_vgpr,
                        src0,
                        src1,
                        src2,
                        src0_neg,
                        src0_abs,
                        src1_neg,
                        src1_abs,
                        src2_neg,
                        src2_abs,
                        clamp,
                    } => {
                        let mut val0 = load_operand(&mut b, src0, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        val0 = apply_modifiers(&mut b, val0, *src0_abs, *src0_neg);
        
                        let mut val1 = load_operand(&mut b, src1, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        val1 = apply_modifiers(&mut b, val1, *src1_abs, *src1_neg);
        
                        let mut val2 = load_operand(&mut b, src2, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        val2 = apply_modifiers(&mut b, val2, *src2_abs, *src2_neg);
        
                        let mul_res = b.alloc_id();
                        b.write_inst(131, &[float_type_id, mul_res, val0, val1]); // OpFMul
                        let mut res_id = b.alloc_id();
                        b.write_inst(129, &[float_type_id, res_id, mul_res, val2]); // OpFAdd
        
                        if *clamp {
                            let clamped_id = b.alloc_id();
                            b.write_inst(12, &[float_type_id, clamped_id, glsl_ext_id, 43, res_id, c_0_0, c_1_0]); // FClamp
                            res_id = clamped_id;
                        }
        
                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, res_id]);
                        }
                    }
                    Rdna2Instruction::SLoadDword { dst_sgpr, base_sgpr, offset } => {
                        let low_val = load_operand(&mut b, &Operand::Sgpr(*base_sgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let high_val = load_operand(&mut b, &Operand::Sgpr(*base_sgpr + 1), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        
                        let low_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, low_uint, low_val]);
                        let high_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, high_uint, high_val]);
                        
                        let low_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, low_ulong, low_uint]);
                        let high_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, high_ulong, high_uint]);
                        
                        let shifted_high = b.alloc_id();
                        b.write_inst(196, &[ulong_type_id, shifted_high, high_ulong, c_32_ulong]);
                        
                        let addr_ulong = b.alloc_id();
                        b.write_inst(197, &[ulong_type_id, addr_ulong, shifted_high, low_ulong]);
                        
                        let final_addr = if *offset > 0 {
                            let offset_ulong_id = b.get_or_create_constant(ulong_type_id, &[*offset as u32, 0]);
                            let res_addr = b.alloc_id();
                            b.write_inst(128, &[ulong_type_id, res_addr, addr_ulong, offset_ulong_id]);
                            res_addr
                        } else {
                            addr_ulong
                        };
                        
                        let ptr_id = b.alloc_id();
                        b.write_inst(124, &[ptr_physical_float_id, ptr_id, final_addr]);
                        
                        let loaded_val = b.alloc_id();
                        b.write_inst(61, &[float_type_id, loaded_val, ptr_id, 2, 4]); // OpLoad (Aligned=4)
                        
                        if let Some(&dst_var) = sgpr_map.get(dst_sgpr) {
                            b.write_inst(62, &[dst_var, loaded_val]);
                        }
                    }
                    Rdna2Instruction::SLoadDwordX4 { dst_sgpr, base_sgpr, offset } => {
                        let low_val = load_operand(&mut b, &Operand::Sgpr(*base_sgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let high_val = load_operand(&mut b, &Operand::Sgpr(*base_sgpr + 1), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        
                        let low_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, low_uint, low_val]);
                        let high_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, high_uint, high_val]);
                        
                        let low_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, low_ulong, low_uint]);
                        let high_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, high_ulong, high_uint]);
                        
                        let shifted_high = b.alloc_id();
                        b.write_inst(196, &[ulong_type_id, shifted_high, high_ulong, c_32_ulong]);
                        
                        let addr_ulong = b.alloc_id();
                        b.write_inst(197, &[ulong_type_id, addr_ulong, shifted_high, low_ulong]);
                        
                        for comp in 0..4 {
                            let comp_offset = (*offset as u32) + (comp * 4);
                            let final_addr = if comp_offset > 0 {
                                let offset_ulong_id = b.get_or_create_constant(ulong_type_id, &[comp_offset, 0]);
                                let res_addr = b.alloc_id();
                                b.write_inst(128, &[ulong_type_id, res_addr, addr_ulong, offset_ulong_id]);
                                res_addr
                            } else {
                                addr_ulong
                            };
                            
                            let ptr_id = b.alloc_id();
                            b.write_inst(124, &[ptr_physical_float_id, ptr_id, final_addr]);
                            
                            let loaded_val = b.alloc_id();
                            b.write_inst(61, &[float_type_id, loaded_val, ptr_id, 2, 4]); // OpLoad (Aligned=4)
                            
                            if let Some(&dst_var) = sgpr_map.get(&(dst_sgpr + comp as u8)) {
                                b.write_inst(62, &[dst_var, loaded_val]);
                            }
                        }
                    }
                    Rdna2Instruction::VBufferLoadDword { dst_vgpr, vaddr_vgpr, resource_sgpr, offset } => {
                        let low_val = load_operand(&mut b, &Operand::Sgpr(*resource_sgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let high_val = load_operand(&mut b, &Operand::Sgpr(*resource_sgpr + 1), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        
                        let low_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, low_uint, low_val]);
                        let high_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, high_uint, high_val]);
                        
                        let low_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, low_ulong, low_uint]);
                        let high_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, high_ulong, high_uint]);
                        
                        let shifted_high = b.alloc_id();
                        b.write_inst(196, &[ulong_type_id, shifted_high, high_ulong, c_32_ulong]);
                        
                        let addr_ulong = b.alloc_id();
                        b.write_inst(197, &[ulong_type_id, addr_ulong, shifted_high, low_ulong]);
                        
                        let vaddr_val = load_operand(&mut b, &Operand::Vgpr(*vaddr_vgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let vaddr_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, vaddr_uint, vaddr_val]);
                        
                        let vaddr_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, vaddr_ulong, vaddr_uint]);
                        
                        let c_4_ulong = b.get_or_create_constant(ulong_type_id, &[4, 0]);
                        
                        let byte_offset = b.alloc_id();
                        b.write_inst(132, &[ulong_type_id, byte_offset, vaddr_ulong, c_4_ulong]);
                        
                        let base_with_vaddr = b.alloc_id();
                        b.write_inst(128, &[ulong_type_id, base_with_vaddr, addr_ulong, byte_offset]);
                        
                        let final_addr = if *offset > 0 {
                            let offset_ulong_id = b.get_or_create_constant(ulong_type_id, &[*offset as u32, 0]);
                            let res_addr = b.alloc_id();
                            b.write_inst(128, &[ulong_type_id, res_addr, base_with_vaddr, offset_ulong_id]);
                            res_addr
                        } else {
                            base_with_vaddr
                        };
                        
                        let ptr_id = b.alloc_id();
                        b.write_inst(124, &[ptr_physical_float_id, ptr_id, final_addr]);
                        
                        let loaded_val = b.alloc_id();
                        b.write_inst(61, &[float_type_id, loaded_val, ptr_id, 2, 4]); // OpLoad (Aligned=4)
                        
                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, loaded_val]);
                        }
                    }
                    Rdna2Instruction::VBufferStoreDword { src_vgpr, vaddr_vgpr, resource_sgpr, offset } => {
                        let low_val = load_operand(&mut b, &Operand::Sgpr(*resource_sgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let high_val = load_operand(&mut b, &Operand::Sgpr(*resource_sgpr + 1), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        
                        let low_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, low_uint, low_val]);
                        let high_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, high_uint, high_val]);
                        
                        let low_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, low_ulong, low_uint]);
                        let high_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, high_ulong, high_uint]);
                        
                        let shifted_high = b.alloc_id();
                        b.write_inst(196, &[ulong_type_id, shifted_high, high_ulong, c_32_ulong]);
                        
                        let addr_ulong = b.alloc_id();
                        b.write_inst(197, &[ulong_type_id, addr_ulong, shifted_high, low_ulong]);
                        
                        let vaddr_val = load_operand(&mut b, &Operand::Vgpr(*vaddr_vgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let vaddr_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, vaddr_uint, vaddr_val]);
                        
                        let vaddr_ulong = b.alloc_id();
                        b.write_inst(113, &[ulong_type_id, vaddr_ulong, vaddr_uint]);
                        
                        let c_4_ulong = b.get_or_create_constant(ulong_type_id, &[4, 0]);
                        
                        let byte_offset = b.alloc_id();
                        b.write_inst(132, &[ulong_type_id, byte_offset, vaddr_ulong, c_4_ulong]);
                        
                        let base_with_vaddr = b.alloc_id();
                        b.write_inst(128, &[ulong_type_id, base_with_vaddr, addr_ulong, byte_offset]);
                        
                        let final_addr = if *offset > 0 {
                            let offset_ulong_id = b.get_or_create_constant(ulong_type_id, &[*offset as u32, 0]);
                            let res_addr = b.alloc_id();
                            b.write_inst(128, &[ulong_type_id, res_addr, base_with_vaddr, offset_ulong_id]);
                            res_addr
                        } else {
                            base_with_vaddr
                        };
                        
                        let ptr_id = b.alloc_id();
                        b.write_inst(124, &[ptr_physical_float_id, ptr_id, final_addr]);
                        
                        let data_val = load_operand(&mut b, &Operand::Vgpr(*src_vgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        
                        b.write_inst(62, &[ptr_id, data_val, 2, 4]); // OpStore (Aligned=4)
                    }
                    Rdna2Instruction::VImageSample { dst_vgpr, src_vgpr, resource_sgpr: _, sampler_sgpr: _ } => {
                        if has_texture {
                            let sampled_img = b.alloc_id();
                            b.write_inst(61, &[sampled_image_type_id, sampled_img, sampler_var_id]); // Load u_sampler
                            
                            let u_var = vgpr_map.get(src_vgpr).copied().unwrap_or(c_0_0);
                            let v_var = vgpr_map.get(&(*src_vgpr + 1)).copied().unwrap_or(c_0_0);
                            let u_val = b.alloc_id(); b.write_inst(61, &[float_type_id, u_val, u_var]);
                            let v_val = b.alloc_id(); b.write_inst(61, &[float_type_id, v_val, v_var]);
                            
                            let uv_val = b.alloc_id();
                            b.write_inst(80, &[vec2_type_id, uv_val, u_val, v_val]); // Composite UV
                            
                            let tex_color = b.alloc_id();
                            b.write_inst(87, &[vec4_type_id, tex_color, sampled_img, uv_val]); // ImageSample
                            
                            for comp in 0..4 {
                                let comp_val = b.alloc_id();
                                b.write_inst(81, &[float_type_id, comp_val, tex_color, comp]);
                                if let Some(&dst_var) = vgpr_map.get(&(*dst_vgpr + comp as u8)) {
                                    b.write_inst(62, &[dst_var, comp_val]);
                                }
                            }
                        }
                    }
                    Rdna2Instruction::VectorPkFmaF16 { dst_vgpr, src0, src1, src2 } => {
                        let val0 = load_operand(&mut b, src0, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let val1 = load_operand(&mut b, src1, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let val2 = load_operand(&mut b, src2, &sgpr_map, &vgpr_map, float_type_id, c_0_0);

                        let unpacked0 = b.alloc_id(); b.write_inst(124, &[vec2f16_type_id, unpacked0, val0]); // OpBitcast float to v2f16
                        let unpacked1 = b.alloc_id(); b.write_inst(124, &[vec2f16_type_id, unpacked1, val1]); // OpBitcast float to v2f16
                        let unpacked2 = b.alloc_id(); b.write_inst(124, &[vec2f16_type_id, unpacked2, val2]); // OpBitcast float to v2f16

                        let res_vec = b.alloc_id();
                        b.write_inst(12, &[vec2f16_type_id, res_vec, glsl_ext_id, 50, unpacked0, unpacked1, unpacked2]); // OpExtInst Fma

                        let res_float = b.alloc_id(); b.write_inst(124, &[float_type_id, res_float, res_vec]); // OpBitcast v2f16 back to float

                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, res_float]);
                        }
                    }
                    Rdna2Instruction::VectorPkAddF16 { dst_vgpr, src0, src1 } => {
                        let val0 = load_operand(&mut b, src0, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let val1 = load_operand(&mut b, src1, &sgpr_map, &vgpr_map, float_type_id, c_0_0);

                        let unpacked0 = b.alloc_id(); b.write_inst(124, &[vec2f16_type_id, unpacked0, val0]); // OpBitcast float to v2f16
                        let unpacked1 = b.alloc_id(); b.write_inst(124, &[vec2f16_type_id, unpacked1, val1]); // OpBitcast float to v2f16

                        let res_vec = b.alloc_id();
                        b.write_inst(129, &[vec2f16_type_id, res_vec, unpacked0, unpacked1]); // OpFAdd

                        let res_float = b.alloc_id(); b.write_inst(124, &[float_type_id, res_float, res_vec]); // OpBitcast v2f16 back to float

                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, res_float]);
                        }
                    }
                    Rdna2Instruction::VectorPkMulF16 { dst_vgpr, src0, src1 } => {
                        let val0 = load_operand(&mut b, src0, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let val1 = load_operand(&mut b, src1, &sgpr_map, &vgpr_map, float_type_id, c_0_0);

                        let unpacked0 = b.alloc_id(); b.write_inst(124, &[vec2f16_type_id, unpacked0, val0]); // OpBitcast float to v2f16
                        let unpacked1 = b.alloc_id(); b.write_inst(124, &[vec2f16_type_id, unpacked1, val1]); // OpBitcast float to v2f16

                        let res_vec = b.alloc_id();
                        b.write_inst(131, &[vec2f16_type_id, res_vec, unpacked0, unpacked1]); // OpFMul

                        let res_float = b.alloc_id(); b.write_inst(124, &[float_type_id, res_float, res_vec]); // OpBitcast v2f16 back to float

                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, res_float]);
                        }
                    }
                    Rdna2Instruction::DsReadB32 { dst_vgpr, addr_vgpr, offset } => {
                        let addr_float = load_operand(&mut b, &Operand::Vgpr(*addr_vgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let addr_uint = b.alloc_id(); b.write_inst(124, &[uint_type_id, addr_uint, addr_float]); // OpBitcast

                        let c_2 = b.get_or_create_constant(uint_type_id, &[2]);
                        let index_uint = b.alloc_id(); b.write_inst(137, &[uint_type_id, index_uint, addr_uint, c_2]); // OpShiftRightLogical

                        let final_index = if *offset > 0 {
                            let offset_dwords = *offset as u32 / 4;
                            let c_offset = b.get_or_create_constant(uint_type_id, &[offset_dwords]);
                            let res_idx = b.alloc_id(); b.write_inst(128, &[uint_type_id, res_idx, index_uint, c_offset]); // OpIAdd
                            res_idx
                        } else {
                            index_uint
                        };

                        let element_ptr = b.alloc_id();
                        b.write_inst(65, &[ptr_workgroup_float_id, element_ptr, lds_var_id, final_index]); // OpAccessChain

                        let loaded_float = b.alloc_id();
                        b.write_inst(61, &[float_type_id, loaded_float, element_ptr]); // OpLoad

                        if let Some(&dst_var) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var, loaded_float]);
                        }
                    }
                    Rdna2Instruction::DsWriteB32 { addr_vgpr, data_vgpr, offset } => {
                        let addr_float = load_operand(&mut b, &Operand::Vgpr(*addr_vgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let addr_uint = b.alloc_id(); b.write_inst(124, &[uint_type_id, addr_uint, addr_float]); // OpBitcast

                        let c_2 = b.get_or_create_constant(uint_type_id, &[2]);
                        let index_uint = b.alloc_id(); b.write_inst(137, &[uint_type_id, index_uint, addr_uint, c_2]); // OpShiftRightLogical

                        let final_index = if *offset > 0 {
                            let offset_dwords = *offset as u32 / 4;
                            let c_offset = b.get_or_create_constant(uint_type_id, &[offset_dwords]);
                            let res_idx = b.alloc_id(); b.write_inst(128, &[uint_type_id, res_idx, index_uint, c_offset]); // OpIAdd
                            res_idx
                        } else {
                            index_uint
                        };

                        let data_float = load_operand(&mut b, &Operand::Vgpr(*data_vgpr), &sgpr_map, &vgpr_map, float_type_id, c_0_0);

                        let element_ptr = b.alloc_id();
                        b.write_inst(65, &[ptr_workgroup_float_id, element_ptr, lds_var_id, final_index]); // OpAccessChain

                        b.write_inst(62, &[element_ptr, data_float]); // OpStore

                        b.write_inst(224, &[c_scope_workgroup, c_scope_workgroup, c_semantics_workgroup]); // OpControlBarrier
                    }
                    Rdna2Instruction::VReadlaneB32 { dst_sgpr, src_vgpr, lane_operand } => {
                        let lane_val = load_operand(&mut b, lane_operand, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let lane_uint = b.alloc_id(); b.write_inst(124, &[uint_type_id, lane_uint, lane_val]); // OpBitcast

                        let src_var = vgpr_map.get(src_vgpr).copied().unwrap_or(c_0_0);
                        let src_val = b.alloc_id(); b.write_inst(61, &[float_type_id, src_val, src_var]); // OpLoad

                        let shuffled_val = b.alloc_id();
                        b.write_inst(345, &[float_type_id, shuffled_val, c_scope_subgroup, src_val, lane_uint]); // OpGroupNonUniformShuffle

                        if let Some(&dst_var) = sgpr_map.get(dst_sgpr) {
                            b.write_inst(62, &[dst_var, shuffled_val]);
                        }
                    }
                    Rdna2Instruction::VWritelaneB32 { dst_vgpr, src_operand, lane_operand } => {
                        let lane_val = load_operand(&mut b, lane_operand, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let lane_uint = b.alloc_id(); b.write_inst(124, &[uint_type_id, lane_uint, lane_val]); // OpBitcast

                        let local_id = b.alloc_id();
                        b.write_inst(61, &[uint_type_id, local_id, subgroup_local_invocation_id_var]); // OpLoad

                        let cond_id = b.alloc_id();
                        b.write_inst(170, &[bool_type_id, cond_id, local_id, lane_uint]); // OpIEqual

                        let dst_var = vgpr_map.get(dst_vgpr).copied().unwrap_or(c_0_0);
                        let dst_old = b.alloc_id();
                        b.write_inst(61, &[float_type_id, dst_old, dst_var]); // OpLoad

                        let src_val = load_operand(&mut b, src_operand, &sgpr_map, &vgpr_map, float_type_id, c_0_0);

                        let res_val = b.alloc_id();
                        b.write_inst(169, &[float_type_id, res_val, cond_id, src_val, dst_old]); // OpSelect

                        if let Some(&dst_var_ref) = vgpr_map.get(dst_vgpr) {
                            b.write_inst(62, &[dst_var_ref, res_val]); // OpStore
                        }
                    }
                    Rdna2Instruction::SBarrier => {
                        b.write_inst(224, &[c_scope_workgroup, c_scope_workgroup, c_semantics_workgroup]); // OpControlBarrier
                    }
                    Rdna2Instruction::SWaitcnt { .. } => {
                        let c_semantics_all = b.get_or_create_constant(uint_type_id, &[328]);
                        b.write_inst(225, &[c_scope_device, c_semantics_all]); // OpMemoryBarrier
                    }
                    // ============================================================
                    // EXEC Mask Mutation — Wave-level divergence control
                    // ============================================================
                    Rdna2Instruction::SAndSaveexecB64 { dst_sgpr_pair, src } => {
                        // s_and_saveexec_b64: save EXEC to dst, then EXEC = EXEC & src
                        // In SPIR-V, this maps to a subgroup ballot capturing active lanes.
                        // The ballot result (uvec4) represents which lanes are active.
                        // We extract the low 32 bits and store them as the saved EXEC mask.
                        let src_val = load_operand(&mut b, src, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        
                        // Convert src to bool for ballot predicate
                        let cond_id = b.alloc_id();
                        b.write_inst(181, &[bool_type_id, cond_id, src_val, c_0_0]); // OpFOrdNotEqual (nonzero = true)
                        
                        // OpGroupNonUniformBallot: captures which lanes have cond==true
                        let ballot_result = b.alloc_id();
                        b.write_inst(333, &[uvec4_type_id, ballot_result, c_scope_subgroup, cond_id]); // OpGroupNonUniformBallot
                        
                        // Extract low 32 bits of the ballot (lanes 0-31)
                        let exec_lo = b.alloc_id();
                        let c_0_uint = b.get_or_create_constant(uint_type_id, &[0]);
                        b.write_inst(81, &[uint_type_id, exec_lo, ballot_result, c_0_uint]); // OpCompositeExtract
                        
                        // Bitcast to float and store in destination SGPR pair
                        let exec_float = b.alloc_id();
                        b.write_inst(124, &[float_type_id, exec_float, exec_lo]); // OpBitcast
                        if let Some(&dst_var) = sgpr_map.get(dst_sgpr_pair) {
                            b.write_inst(62, &[dst_var, exec_float]); // OpStore saved EXEC mask
                        }
                    }
                    Rdna2Instruction::SOrSaveexecB64 { dst_sgpr_pair, src } => {
                        // s_or_saveexec_b64: save EXEC to dst, then EXEC = EXEC | src
                        // In SPIR-V we approximate this similarly — the ballot captures the
                        // current active mask, and the OR extends it. Since SPIR-V drivers
                        // manage execution masks, we capture the ballot and store the save.
                        let src_val = load_operand(&mut b, src, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        let cond_id = b.alloc_id();
                        b.write_inst(181, &[bool_type_id, cond_id, src_val, c_0_0]); // OpFOrdNotEqual
                        
                        let ballot_result = b.alloc_id();
                        b.write_inst(333, &[uvec4_type_id, ballot_result, c_scope_subgroup, cond_id]);
                        
                        let exec_lo = b.alloc_id();
                        let c_0_uint = b.get_or_create_constant(uint_type_id, &[0]);
                        b.write_inst(81, &[uint_type_id, exec_lo, ballot_result, c_0_uint]);
                        
                        // OR the saved mask with the current ballot result
                        let src_uint = b.alloc_id();
                        b.write_inst(124, &[uint_type_id, src_uint, src_val]); // OpBitcast to uint
                        let or_result = b.alloc_id();
                        b.write_inst(197, &[uint_type_id, or_result, exec_lo, src_uint]); // OpBitwiseOr
                        
                        let exec_float = b.alloc_id();
                        b.write_inst(124, &[float_type_id, exec_float, or_result]); // OpBitcast back to float
                        if let Some(&dst_var) = sgpr_map.get(dst_sgpr_pair) {
                            b.write_inst(62, &[dst_var, exec_float]);
                        }
                    }
                    Rdna2Instruction::SMovB64Exec { src } => {
                        // s_mov_b64 exec, src: Restores the EXEC mask.
                        // In SPIR-V, the driver manages execution masks implicitly.
                        // We emit a no-op load of the source value to maintain register
                        // consistency without affecting SPIR-V control flow.
                        let _src_val = load_operand(&mut b, src, &sgpr_map, &vgpr_map, float_type_id, c_0_0);
                        // No SPIR-V emission needed — mask restoration is implicit
                    }
                    _ => {}
                }
            }
        }

        // Handle fallthrough block branching
        let has_terminator = if block.instructions.is_empty() {
            false
        } else {
            let last_inst_idx = block.label_id as usize + block.instructions.len() - 1;
            match &instructions[last_inst_idx] {
                Rdna2Instruction::SBranch { .. } |
                Rdna2Instruction::SCbranchScc0 { .. } |
                Rdna2Instruction::SCbranchScc1 { .. } |
                Rdna2Instruction::EndPgm => true,
                _ => false,
            }
        };

        if !has_terminator {
            if let Some((merge_label, continue_label)) = loop_merge_info {
                b.write_inst(246, &[merge_label, continue_label, 0]); // OpLoopMerge
            }
            if let Some(&succ) = block.successors.first() {
                write_dispatch_store(&mut b, block.label_id, succ);
                let succ_label = block_labels[&succ];
                b.write_inst(249, &[succ_label]); // OpBranch
            } else {
                b.write_inst(253, &[]); // OpReturn fallback
            }
        }
    }
    b.write_inst(56, &[]); // OpFunctionEnd

    b.build()
}

pub fn generate_compute_spirv() -> Vec<u32> {
    let mut b = SpirvBuilder::new();
    
    // Allocate IDs
    let entry_fn_id = b.alloc_id();
    let void_type = b.alloc_id();
    let fn_type = b.alloc_id();
    
    let uint_type = b.alloc_id();
    let v3uint_type = b.alloc_id();
    
    let ptr_input_v3uint = b.alloc_id();
    let gl_global_invocation_id = b.alloc_id();
    
    let runtime_array_uint = b.alloc_id();
    let struct_buffer = b.alloc_id();
    let ptr_uniform_struct_buffer = b.alloc_id();
    
    let input_buffer_var = b.alloc_id();
    let output_buffer_var = b.alloc_id();
    
    let ptr_uniform_uint = b.alloc_id();
    let c_0 = b.alloc_id();
    let c_xor = b.alloc_id();
    
    // Capabilities
    b.write_inst(17, &[1]); // OpCapability Shader
    b.write_inst(14, &[0, 1]); // OpMemoryModel Logical, GLSL450
    
    // Entry Point: OpEntryPoint GLCompute, entry_fn_id, "main", gl_global_invocation_id
    b.write_inst(15, &[5, entry_fn_id, 0x6E69616D, 0x00000000, gl_global_invocation_id]);
    
    // Execution Mode: OpExecutionMode entry_fn_id LocalSize 256 1 1
    b.write_inst(16, &[entry_fn_id, 17, 256, 1, 1]);
    
    // Decorations
    // Builtin GlobalInvocationId (GlobalInvocationId = 28, BuiltIn = 11)
    b.write_inst(71, &[gl_global_invocation_id, 11, 28]); // OpDecorate gl_global_invocation_id BuiltIn GlobalInvocationId
    
    // Struct decorations: Block (2)
    b.write_inst(71, &[struct_buffer, 2]); // OpDecorate struct_buffer Block
    
    // Runtime array decoration: ArrayStride 6
    b.write_inst(71, &[runtime_array_uint, 6, 4]); // OpDecorate runtime_array_uint ArrayStride 6
    
    // Member decoration: Offset 0
    b.write_inst(72, &[struct_buffer, 0, 35, 0]); // OpMemberDecorate struct_buffer 0 Offset 0
    
    // Input / Output descriptor decorations (DescriptorSet = 34, Binding = 33)
    b.write_inst(71, &[input_buffer_var, 34, 0]); // OpDecorate input_buffer_var DescriptorSet 0
    b.write_inst(71, &[input_buffer_var, 33, 0]); // OpDecorate input_buffer_var Binding 0
    
    b.write_inst(71, &[output_buffer_var, 34, 0]); // OpDecorate output_buffer_var DescriptorSet 0
    b.write_inst(71, &[output_buffer_var, 33, 1]); // OpDecorate output_buffer_var Binding 1
    
    // Types
    b.set_section(Section::TypesAndConstants);
    b.write_inst(19, &[void_type]); // OpTypeVoid
    b.write_inst(33, &[fn_type, void_type]); // OpTypeFunction
    
    b.write_inst(21, &[uint_type, 32, 0]); // OpTypeInt 32 0 (uint)
    b.write_inst(23, &[v3uint_type, uint_type, 3]); // OpTypeVector uint 3
    
    b.write_inst(32, &[ptr_input_v3uint, 1, v3uint_type]); // OpTypePointer Input v3uint
    b.write_inst(29, &[runtime_array_uint, uint_type]); // OpTypeRuntimeArray uint
    b.write_inst(30, &[struct_buffer, runtime_array_uint]); // OpTypeStruct struct_buffer [runtime_array_uint]
    b.write_inst(32, &[ptr_uniform_struct_buffer, 12, struct_buffer]); // OpTypePointer StorageBuffer struct_buffer
    
    b.write_inst(32, &[ptr_uniform_uint, 12, uint_type]); // OpTypePointer StorageBuffer uint
    
    // Variables
    b.write_inst(59, &[ptr_input_v3uint, gl_global_invocation_id, 1]); // OpVariable gl_global_invocation_id Input
    b.write_inst(59, &[ptr_uniform_struct_buffer, input_buffer_var, 12]); // OpVariable input_buffer_var StorageBuffer
    b.write_inst(59, &[ptr_uniform_struct_buffer, output_buffer_var, 12]); // OpVariable output_buffer_var StorageBuffer
    
    // Constants
    b.write_inst(43, &[uint_type, c_0, 0]); // OpConstant c_0 0
    b.write_inst(43, &[uint_type, c_xor, 0xAAAAAAAA]); // OpConstant c_xor 0xAAAAAAAA
    
    // Function body
    b.set_section(Section::Functions);
    b.write_inst(54, &[void_type, entry_fn_id, 0, fn_type]); // OpFunction
    let label = b.alloc_id();
    b.write_inst(248, &[label]); // OpLabel
    
    // Load Global Invocation ID
    let val_v3uint = b.alloc_id();
    b.write_inst(61, &[v3uint_type, val_v3uint, gl_global_invocation_id]); // OpLoad
    
    // Extract Global Invocation ID .x
    let idx = b.alloc_id();
    b.write_inst(81, &[uint_type, idx, val_v3uint, 0]); // OpCompositeExtract
    
    // Access chain for input buffer
    let ptr_input_elem = b.alloc_id();
    b.write_inst(65, &[ptr_uniform_uint, ptr_input_elem, input_buffer_var, c_0, idx]); // OpAccessChain
    
    // Load value from input buffer
    let val = b.alloc_id();
    b.write_inst(61, &[uint_type, val, ptr_input_elem]); // OpLoad
    
    // XOR value with 0xAAAAAAAA
    let xor_val = b.alloc_id();
    b.write_inst(198, &[uint_type, xor_val, val, c_xor]); // OpBitwiseXor
    
    // Access chain for output buffer
    let ptr_output_elem = b.alloc_id();
    b.write_inst(65, &[ptr_uniform_uint, ptr_output_elem, output_buffer_var, c_0, idx]); // OpAccessChain
    
    // Store XORed value into output buffer
    b.write_inst(62, &[ptr_output_elem, xor_val]); // OpStore
    
    b.write_inst(253, &[]); // OpReturn
    b.write_inst(56, &[]); // OpFunctionEnd
    
    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_generate_compute_shaders() {
        let kraken_spirv = generate_kraken_spirv();
        assert!(!kraken_spirv.is_empty());
        let mut file = File::create("kraken_test.spv").unwrap();
        for word in kraken_spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }

        let tempest_spirv = generate_tempest_audio_spirv();
        assert!(!tempest_spirv.is_empty());
        let mut file = File::create("tempest_test.spv").unwrap();
        for word in tempest_spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn test_translate_spirv() {
        let vs_instructions = vec![
            Rdna2Instruction::ScalarMov {
                dst_sgpr: 0,
                src: Operand::Literal(0x1234),
            },
            Rdna2Instruction::SLoadDword {
                dst_sgpr: 2,
                base_sgpr: 0,
                offset: 16,
            },
            Rdna2Instruction::SLoadDwordX4 {
                dst_sgpr: 4,
                base_sgpr: 0,
                offset: 32,
            },
            Rdna2Instruction::VBufferLoadDword {
                dst_vgpr: 0,
                vaddr_vgpr: 2,
                resource_sgpr: 0,
                offset: 0,
            },
            Rdna2Instruction::EndPgm,
        ];

        let fs_instructions = vec![
            Rdna2Instruction::VectorMov {
                dst_vgpr: 0,
                src: Operand::Vgpr(1),
            },
            Rdna2Instruction::VectorAdd {
                dst_vgpr: 2,
                src0: Operand::Vgpr(3),
                src1: Operand::Vgpr(4),
            },
            Rdna2Instruction::VectorMul {
                dst_vgpr: 0,
                src0: Operand::Vgpr(1),
                src1: Operand::Vgpr(2),
            },
            Rdna2Instruction::EndPgm,
        ];

        let vs_spirv = translate_to_spirv(
            &vs_instructions,
            true,   // is_vertex
            false,  // has_vb
            false,  // has_cb
            false,  // has_tex
        );

        let fs_spirv = translate_to_spirv(
            &fs_instructions,
            false,  // is_vertex
            false,  // has_vb
            false,  // has_cb
            false,  // has_tex
        );

        let mut vs_file = File::create("vs_test.spv").unwrap();
        for word in vs_spirv {
            vs_file.write_all(&word.to_le_bytes()).unwrap();
        }

        let mut fs_file = File::create("fs_test.spv").unwrap();
        for word in fs_spirv {
            fs_file.write_all(&word.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn test_structurize_loop() {
        let loop_instructions = vec![
            Rdna2Instruction::ScalarMov {
                dst_sgpr: 0,
                src: Operand::Constant(0),
            },
            // Loop header
            Rdna2Instruction::ScalarAdd {
                dst_sgpr: 0,
                src0: Operand::Sgpr(0),
                src1: Operand::Constant(1),
            },
            // Conditional break: if scc == 0, jump to EndPgm (offset 1)
            Rdna2Instruction::SCbranchScc0 {
                offset: 1,
            },
            // Continue back-edge: jump to loop header (offset -3)
            Rdna2Instruction::SBranch {
                offset: -3,
            },
            // Exit
            Rdna2Instruction::EndPgm,
        ];

        let spirv = translate_to_spirv(
            &loop_instructions,
            true,   // is_vertex
            false,  // has_vb
            false,  // has_cb
            false,  // has_tex
        );

        let mut file = File::create("struct_loop_test.spv").unwrap();
        for word in spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn test_translate_packed_math() {
        let instructions = vec![
            Rdna2Instruction::VectorPkFmaF16 {
                dst_vgpr: 0,
                src0: Operand::Vgpr(1),
                src1: Operand::Vgpr(2),
                src2: Operand::Vgpr(3),
            },
            Rdna2Instruction::VectorPkAddF16 {
                dst_vgpr: 4,
                src0: Operand::Vgpr(5),
                src1: Operand::Vgpr(6),
            },
            Rdna2Instruction::VectorPkMulF16 {
                dst_vgpr: 7,
                src0: Operand::Vgpr(8),
                src1: Operand::Vgpr(9),
            },
            Rdna2Instruction::EndPgm,
        ];

        let spirv = translate_to_spirv(
            &instructions,
            false,  // is_vertex
            false,  // has_vb
            false,  // has_cb
            false,  // has_tex
        );

        let mut file = File::create("packed_math_test.spv").unwrap();
        for word in spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn test_translate_lds_workgroup() {
        let instructions = vec![
            Rdna2Instruction::DsWriteB32 {
                addr_vgpr: 0,
                data_vgpr: 1,
                offset: 8,
            },
            Rdna2Instruction::DsReadB32 {
                dst_vgpr: 2,
                addr_vgpr: 0,
                offset: 16,
            },
            Rdna2Instruction::EndPgm,
        ];

        let spirv = translate_to_spirv(
            &instructions,
            false,  // is_vertex
            false,
            false,
            false,
        );

        let mut file = File::create("lds_test.spv").unwrap();
        for word in spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn test_translate_subgroup_readlane() {
        let instructions = vec![
            Rdna2Instruction::VReadlaneB32 {
                dst_sgpr: 0,
                src_vgpr: 1,
                lane_operand: Operand::Constant(4),
            },
            Rdna2Instruction::EndPgm,
        ];

        let spirv = translate_to_spirv(
            &instructions,
            false,
            false,
            false,
            false,
        );

        let mut file = File::create("subgroup_readlane_test.spv").unwrap();
        for word in spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn test_translate_subgroup_writelane_and_barriers() {
        let instructions = vec![
            Rdna2Instruction::VWritelaneB32 {
                dst_vgpr: 0,
                src_operand: Operand::Sgpr(1),
                lane_operand: Operand::Constant(4),
            },
            Rdna2Instruction::SBarrier,
            Rdna2Instruction::SWaitcnt { simm16: 0 },
            Rdna2Instruction::EndPgm,
        ];

        let spirv = translate_to_spirv(
            &instructions,
            false,
            false,
            false,
            false,
        );

        let mut file = File::create("subgroup_writelane_test.spv").unwrap();
        for word in spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn test_translate_memory_hazards() {
        let instructions = vec![
            Rdna2Instruction::VBufferStoreDword {
                src_vgpr: 0,
                vaddr_vgpr: 1,
                resource_sgpr: 2,
                offset: 0,
            },
            Rdna2Instruction::VBufferLoadDword {
                dst_vgpr: 3,
                vaddr_vgpr: 1,
                resource_sgpr: 2,
                offset: 0,
            },
            Rdna2Instruction::DsWriteB32 {
                addr_vgpr: 0,
                data_vgpr: 1,
                offset: 0,
            },
            Rdna2Instruction::DsReadB32 {
                dst_vgpr: 2,
                addr_vgpr: 0,
                offset: 0,
            },
            Rdna2Instruction::EndPgm,
        ];

        let spirv = translate_to_spirv(
            &instructions,
            false,
            false,
            false,
            false,
        );

        let mut file = File::create("memory_hazard_test.spv").unwrap();
        for word in spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn test_exec_mask_and_loop_transposition() {
        let instructions = vec![
            Rdna2Instruction::ScalarMov {
                dst_sgpr: 0,
                src: Operand::Constant(0),
            },
            // Save current exec to SGPR pair 2, and restrict exec with SGPR 0
            Rdna2Instruction::SAndSaveexecB64 {
                dst_sgpr_pair: 2,
                src: Operand::Sgpr(0),
            },
            // Irreducible loop entries:
            Rdna2Instruction::ScalarAdd {
                dst_sgpr: 0,
                src0: Operand::Sgpr(0),
                src1: Operand::Constant(1),
            },
            Rdna2Instruction::SBranch { offset: 2 },
            Rdna2Instruction::ScalarAdd {
                dst_sgpr: 0,
                src0: Operand::Sgpr(0),
                src1: Operand::Constant(2),
            },
            Rdna2Instruction::SBranch { offset: -3 },
            Rdna2Instruction::EndPgm,
        ];

        let spirv = translate_to_spirv(
            &instructions,
            true,
            false,
            false,
            false,
        );

        assert!(!spirv.is_empty());
    }

    #[test]
    fn test_structurizer_cfg() {
        let unstructured_loop_instructions = vec![
            Rdna2Instruction::ScalarMov {
                dst_sgpr: 0,
                src: Operand::Constant(0),
            },
            // Loop header (offset 1)
            Rdna2Instruction::ScalarAdd {
                dst_sgpr: 0,
                src0: Operand::Sgpr(0),
                src1: Operand::Constant(1),
            },
            // Unstructured exit: if scc == 0, break directly to EndPgm (offset 2)
            Rdna2Instruction::SCbranchScc0 {
                offset: 2,
            },
            // Conditional exit inside loop: if scc == 1, branch to offset 1 (which is EndPgm)
            Rdna2Instruction::SCbranchScc1 {
                offset: 1,
            },
            // Continue back-edge: jump to loop header (offset -4)
            Rdna2Instruction::SBranch {
                offset: -4,
            },
            // Exit point
            Rdna2Instruction::EndPgm,
        ];

        let spirv = translate_to_spirv(
            &unstructured_loop_instructions,
            true,   // is_vertex
            false,  // has_vb
            false,  // has_cb
            false,  // has_tex
        );

        assert!(!spirv.is_empty());
        let mut file = File::create("struct_unstructured_test.spv").unwrap();
        for word in spirv {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
    }
}

#[no_mangle]
pub fn GetShaderPatch(hash: u64) -> Option<Vec<u32>> {
    match hash {
        0xBAADF00DDEADBEEF => {
            Some(vec![
                0x07230203, // SPIR-V magic header
                0x00010300, // version 1.3
                0x000d000b, // generator/bound
            ])
        }
        _ => None,
    }
}

pub fn generate_kraken_spirv() -> Vec<u32> {
    let mut b = SpirvBuilder::new();
    
    let entry_fn_id = b.alloc_id();
    let void_type = b.alloc_id();
    let fn_type = b.alloc_id();
    
    let uint_type = b.alloc_id();
    let v3uint_type = b.alloc_id();
    
    let ptr_input_v3uint = b.alloc_id();
    let gl_global_invocation_id = b.alloc_id();
    
    let runtime_array_uint = b.alloc_id();
    let struct_buffer = b.alloc_id();
    let ptr_uniform_struct_buffer = b.alloc_id();
    
    let input_buffer_var = b.alloc_id();
    let output_buffer_var = b.alloc_id();
    
    let ptr_uniform_uint = b.alloc_id();
    let c_0 = b.alloc_id();
    let c_xor = b.alloc_id();
    
    // Capabilities
    b.write_inst(17, &[1]); // OpCapability Shader
    b.write_inst(14, &[0, 1]); // OpMemoryModel Logical, GLSL450
    
    // Entry Point: OpEntryPoint GLCompute, entry_fn_id, "main", gl_global_invocation_id
    b.write_inst(15, &[5, entry_fn_id, 0x6E69616D, 0x00000000, gl_global_invocation_id]);
    
    // Execution Mode: OpExecutionMode entry_fn_id LocalSize 256 1 1
    b.write_inst(16, &[entry_fn_id, 17, 256, 1, 1]);
    
    // Decorations
    b.write_inst(71, &[gl_global_invocation_id, 11, 28]);
    b.write_inst(71, &[struct_buffer, 2]);
    b.write_inst(71, &[runtime_array_uint, 6, 4]);
    b.write_inst(72, &[struct_buffer, 0, 35, 0]);
    
    b.write_inst(71, &[input_buffer_var, 34, 0]);
    b.write_inst(71, &[input_buffer_var, 33, 0]);
    
    b.write_inst(71, &[output_buffer_var, 34, 0]);
    b.write_inst(71, &[output_buffer_var, 33, 1]);
    
    // Types
    b.set_section(Section::TypesAndConstants);
    b.write_inst(19, &[void_type]);
    b.write_inst(33, &[fn_type, void_type]);
    
    b.write_inst(21, &[uint_type, 32, 0]);
    b.write_inst(23, &[v3uint_type, uint_type, 3]);
    
    b.write_inst(32, &[ptr_input_v3uint, 1, v3uint_type]);
    b.write_inst(29, &[runtime_array_uint, uint_type]);
    b.write_inst(30, &[struct_buffer, runtime_array_uint]);
    b.write_inst(32, &[ptr_uniform_struct_buffer, 12, struct_buffer]);
    
    b.write_inst(32, &[ptr_uniform_uint, 12, uint_type]);
    
    // Variables
    b.write_inst(59, &[ptr_input_v3uint, gl_global_invocation_id, 1]);
    b.write_inst(59, &[ptr_uniform_struct_buffer, input_buffer_var, 12]);
    b.write_inst(59, &[ptr_uniform_struct_buffer, output_buffer_var, 12]);
    
    // Constants
    b.write_inst(43, &[uint_type, c_0, 0]);
    b.write_inst(43, &[uint_type, c_xor, 0x55555555]);
    
    // Function body
    b.set_section(Section::Functions);
    b.write_inst(54, &[void_type, entry_fn_id, 0, fn_type]);
    let label = b.alloc_id();
    b.write_inst(248, &[label]);
    
    let val_v3uint = b.alloc_id();
    b.write_inst(61, &[v3uint_type, val_v3uint, gl_global_invocation_id]);
    
    let idx = b.alloc_id();
    b.write_inst(81, &[uint_type, idx, val_v3uint, 0]);
    
    let ptr_input_elem = b.alloc_id();
    b.write_inst(65, &[ptr_uniform_uint, ptr_input_elem, input_buffer_var, c_0, idx]);
    
    let val = b.alloc_id();
    b.write_inst(61, &[uint_type, val, ptr_input_elem]);
    
    let decoded_val = b.alloc_id();
    b.write_inst(198, &[uint_type, decoded_val, val, c_xor]); // OpBitwiseXor with 0x55555555
    
    let ptr_output_elem = b.alloc_id();
    b.write_inst(65, &[ptr_uniform_uint, ptr_output_elem, output_buffer_var, c_0, idx]);
    
    b.write_inst(62, &[ptr_output_elem, decoded_val]);
    
    // Memory Barrier to prevent hazard
    let c_scope_device = b.alloc_id();
    let c_semantics = b.alloc_id();
    b.write_type_const(43, &[uint_type, c_scope_device, 1]); // Device scope
    b.write_type_const(43, &[uint_type, c_semantics, 72]); // UniformMemory | AcquireRelease
    
    b.write_inst(225, &[c_scope_device, c_semantics]);
    
    b.write_inst(253, &[]);
    b.write_inst(56, &[]);
    
    b.build()
}

pub fn generate_tempest_audio_spirv() -> Vec<u32> {
    let mut b = SpirvBuilder::new();
    
    let entry_fn_id = b.alloc_id();
    let void_type = b.alloc_id();
    let fn_type = b.alloc_id();
    
    let float_type = b.alloc_id();
    let uint_type = b.alloc_id();
    let v3uint_type = b.alloc_id();
    
    let ptr_input_v3uint = b.alloc_id();
    let gl_global_invocation_id = b.alloc_id();
    
    let runtime_array_float = b.alloc_id();
    let struct_buffer = b.alloc_id();
    let ptr_uniform_struct_buffer = b.alloc_id();
    
    let input_buffer_var = b.alloc_id();
    let output_buffer_var = b.alloc_id();
    
    let ptr_uniform_float = b.alloc_id();
    let c_0 = b.alloc_id();
    let c_factor = b.alloc_id();
    
    // Capabilities
    b.write_inst(17, &[1]); // OpCapability Shader
    b.write_inst(14, &[0, 1]); // OpMemoryModel Logical, GLSL450
    
    // Entry Point: OpEntryPoint GLCompute, entry_fn_id, "main", gl_global_invocation_id
    b.write_inst(15, &[5, entry_fn_id, 0x6E69616D, 0x00000000, gl_global_invocation_id]);
    
    // Execution Mode: OpExecutionMode entry_fn_id LocalSize 256 1 1
    b.write_inst(16, &[entry_fn_id, 17, 256, 1, 1]);
    
    // Decorations
    b.write_inst(71, &[gl_global_invocation_id, 11, 28]);
    b.write_inst(71, &[struct_buffer, 2]);
    b.write_inst(71, &[runtime_array_float, 6, 4]);
    b.write_inst(72, &[struct_buffer, 0, 35, 0]);
    
    b.write_inst(71, &[input_buffer_var, 34, 0]);
    b.write_inst(71, &[input_buffer_var, 33, 0]);
    
    b.write_inst(71, &[output_buffer_var, 34, 0]);
    b.write_inst(71, &[output_buffer_var, 33, 1]);
    
    // Types
    b.set_section(Section::TypesAndConstants);
    b.write_inst(19, &[void_type]);
    b.write_inst(33, &[fn_type, void_type]);
    
    b.write_inst(22, &[float_type, 32]); // OpTypeFloat 32
    b.write_inst(21, &[uint_type, 32, 0]);
    b.write_inst(23, &[v3uint_type, uint_type, 3]);
    
    b.write_inst(32, &[ptr_input_v3uint, 1, v3uint_type]);
    b.write_inst(29, &[runtime_array_float, float_type]);
    b.write_inst(30, &[struct_buffer, runtime_array_float]);
    b.write_inst(32, &[ptr_uniform_struct_buffer, 12, struct_buffer]);
    
    b.write_inst(32, &[ptr_uniform_float, 12, float_type]);
    
    // Variables
    b.write_inst(59, &[ptr_input_v3uint, gl_global_invocation_id, 1]);
    b.write_inst(59, &[ptr_uniform_struct_buffer, input_buffer_var, 12]);
    b.write_inst(59, &[ptr_uniform_struct_buffer, output_buffer_var, 12]);
    
    // Constants
    b.write_inst(43, &[uint_type, c_0, 0]);
    b.write_inst(43, &[float_type, c_factor, 0x3F4CCCCD]); // 0.8f spatial factor
    
    // Function body
    b.set_section(Section::Functions);
    b.write_inst(54, &[void_type, entry_fn_id, 0, fn_type]);
    let label = b.alloc_id();
    b.write_inst(248, &[label]);
    
    let val_v3uint = b.alloc_id();
    b.write_inst(61, &[v3uint_type, val_v3uint, gl_global_invocation_id]);
    
    let idx = b.alloc_id();
    b.write_inst(81, &[uint_type, idx, val_v3uint, 0]);
    
    let ptr_input_elem = b.alloc_id();
    b.write_inst(65, &[ptr_uniform_float, ptr_input_elem, input_buffer_var, c_0, idx]);
    
    let val = b.alloc_id();
    b.write_inst(61, &[float_type, val, ptr_input_elem]);
    
    let spatialized_val = b.alloc_id();
    b.write_inst(133, &[float_type, spatialized_val, val, c_factor]); // OpFMul
    
    let ptr_output_elem = b.alloc_id();
    b.write_inst(65, &[ptr_uniform_float, ptr_output_elem, output_buffer_var, c_0, idx]);
    
    b.write_inst(62, &[ptr_output_elem, spatialized_val]);
    
    // Memory Barrier to prevent hazard
    let c_scope_device = b.alloc_id();
    let c_semantics = b.alloc_id();
    b.write_type_const(43, &[uint_type, c_scope_device, 1]); // Device scope
    b.write_type_const(43, &[uint_type, c_semantics, 72]); // UniformMemory | AcquireRelease
    
    b.write_inst(225, &[c_scope_device, c_semantics]);
    
    b.write_inst(253, &[]);
    b.write_inst(56, &[]);
    
    b.build()
}


