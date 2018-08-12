import ipdb
import random
import string as STRING

class register():
    SR_CARRY_BIT = 1
    SR_ZERO_BIT = 1 << 1
    SR_NEG_BIT = 1 << 2
    SR_OVERFLOW = 1 << 3
    REFER_DADD_CONST = '3c01' 
    def __init__(self): 
        self.SR = 0
    
    def add_registers(self, R1, R2):
        if(len(R1) > 4 or len(R2) > 4):
            print("Error! function use for 2Byte register only")
        
        self.SR = 0 
        int_return_value = int(R1, 16) + int(R2, 16)
       
        if (int_return_value > 0xFFFF):
            self.SR = self.SR | self.SR_CARRY_BIT
            int_return_value - 0x10000
        hex_return = hex(int_return_value)[2:]
        if(hex_return == '0000'):
            self.SR = self.SR | self.SR_ZERO_BIT
        if(int(hex_return, 16) > 0x7FFF):
            self.SR = self.SR | self.SR_NEG_BIT

        return hex_return[-4:] if len(hex_return) > 4 else "{:>04}".format(hex_return)
    
    
    def sub_registers(self, R1, R2):
        if(len(R1) > 4 or len(R2) > 4):
            print("Error! function use for 2Byte register only")
        self.SR = 0 
        if(int(R2, 16) < int(R1, 16)):
            int_return_value = int(R2, 16) - int(R1, 16) + 0x10000
        else:
            int_return_value = int(R2, 16) - int(R1, 16)
        if (int_return_value > 0x7FFF):
            self.SR = self.SR | self.SR_NEG_BIT
        if (int(R2, 16) > int(R1, 16)):
            self.SR = self.SR | self.SR_CARRY_BIT
        if (int_return_value == 0):
            self.SR = self.SR | self.SR_ZERO_BIT
        hex_return = hex(int_return_value)[2:]
        
        return hex_return[-4:] if len(hex_return) > 4 else "{:>04}".format(hex_return)
    
    @staticmethod
    def swap_byte(register):
        return register[2:] + register[:2]

    def rrc_registers(self, register):
        register_value = int(register, 16)
        sr_carry_bit = register_value & 1
        register_value = register_value >> 1
        register_value = register_value | (0x8000 if (self.SR & self.SR_CARRY_BIT) else 0x0000)
        register = hex(register_value)[2:]
        self.SR = self.SR | (self.SR_NEG_BIT if register_value > 0x8000 else 0)
        self.SR = self.SR | (0 if sr_carry_bit == 0 else self.SR_CARRY_BIT)
        return register[-4:] if len( register) > 4 else "{:>04}".format(register)


    def rra_registers(self, register):
        register_value = int(register, 16)
        if register_value > 0x8000:
            self.SR = self.SR | self.SR_NEG_BIT
        register_value = (register_value >> 1) | (0x8000 if (register_value > 0x8000) else 0x0000)
        register = hex(register_value)[2:]
        return register[-4:] if len( register) > 4 else "{:>04}".format(register)

    def dadd_registers(self, R1, R2):
        if(len(R1) > 4 or len(R2) > 4):
            print("Error! function use for 2Byte register only")
        string = []
        unit = 1
        tmp = int(R1[-1:], 16) + int(R2[-1:], 16)
        carry = (1 if tmp > 9 else 0)
        if carry == 1:
            string.insert(0, hex(tmp - 10)[-1:])
        else:
            string.insert(0, hex(tmp)[-1:])
        while unit < len(R1 if int(R1, 16) > int(R2, 16) else R2):
            tmp = carry +int(R1[-1 - unit:-unit], 16) + int(R2[-1 - unit:-unit], 16)
            carry= (1 if tmp > 9 else 0) 
            if carry == 1:
                string.insert(0, hex(tmp - 10)[-1:])
                self.SR = self.SR | self.SR_CARRY_BIT
            else:
                string.insert(0, hex(tmp)[-1:])
                self.SR = self.SR & (self.SR_CARRY_BIT ^ 0xFFFF)
            unit= unit + 1
        return str(''.join(string))

    @staticmethod 
    def read_mem(image, address):
        return image[address + 2:address + 4] + image[address:address + 2]

    @staticmethod 
    def xor_registers( R1, R2):
        hex_string = hex(int(R1, 16) ^ int(R2, 16))[2:]
        return hex_string[:4] if len(hex_string) > 4 else "{:>04}".format(hex_string)

    @staticmethod 
    def and_registers( R1, R2):
        hex_string = hex(int(R1, 16) ^ int(R2, 16))[2:]
        return hex_string[:4] if len(hex_string) > 4 else "{:>04}".format(hex_string)

    @staticmethod 
    def or_registers( R1, R2):
        hex_string = hex(int(R1, 16) ^ int(R2, 16))[2:]
        return hex_string[:4] if len(hex_string) > 4 else "{:>04}".format(hex_string)

def decrypt_hash_function(R10, R15):
    """have 2 argument is 2Byte size register R10 and R15 return decrypted instruction. R10 is encrypted address, \
    R15 is intruction value"""

    if(len(R10) != 4 or len(R15) != 4):
	print("Error! function use for 2Byte register only")
	return 0
    
    reg_sim = register()
    R14 = R10[:]
    #print('[debug info intruction mov.w   R10, R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = register.swap_byte(R14)
    #print('[debug info intruction swpb    R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.sub_registers('04d2', R14)
    #print('[debug info intruction sub.w   #4D2h, R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.add_registers(str(reg_sim.SR), R14)
    #print('[debug info intruction add.w   SR, R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.rrc_registers(R14)
    #print('[debug info intruction rrc.w   R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.dadd_registers(R10, R14)
    #print('[debug info intruction dadd.w  R10, R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.rra_registers(R14)
    #print('[debug info intruction rra.w   R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.rrc_registers(R14)
    #print('[debug info intruction rrc.w   R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.dadd_registers(register.REFER_DADD_CONST, R14)
    #print('[debug info intruction dadd.w  @PC, R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.add_registers(str(reg_sim.SR), R14)
    #print('[debug info intruction add.w   SR, R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.rrc_registers(R14)
    #print('[debug info intruction rrc.w   R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.add_registers('100e', R14)
    #print('[debug info intruction add.w   @PC, R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.rrc_registers(R14)
    #print('[debug info intruction rrc.w   R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R14 = reg_sim.rrc_registers(R14)
    #print('[debug info intruction rrc.w   R14] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))
    R15 = reg_sim.xor_registers(R14, R15)
    #print('[debug info intruction xor.w   R14, R15] R10: {}, R14: {}, R15: {}, SR: {}'.format(R10, R14, R15, reg_sim.SR))

    return R15 if len(R15) == 4 else "{:>04}".format(R15)

def block_decrypt(file_image, start_addr):

    A_BYTE_STEP = 2
    A_WORD_STEP = 4
    OFF_SET = -9112
    instructions_decrypted = []

    for i in  range(7):
        R10 = hex(int(start_addr, 16) + A_BYTE_STEP)[2:6]
        ptr = int(start_addr, 16)*A_BYTE_STEP + OFF_SET
        R15 = register.read_mem(file_image, ptr)
        instruction = decrypt_hash_function(R10, R15)
        instructions_decrypted.append(register.swap_byte(instruction))
        #print('---------------decrypt instruction at address: [{}] from {} to {}-------------'.format(start_addr, R15, instruction))
        start_addr = R10

    return instructions_decrypted
def final_decryptation(file_image, start_address = '160c'):
    # start_addr = 160c
    deobfucate = []
    count_down = 5
    anti_loop_address = []
    address = start_address
    while(True):
        decrypted_instruction = ''.join(block_decrypt(file_image, address))
        # find branch r13 instruction
        ptr_mv_R12 = decrypted_instruction.find('3c40')
        ptr_br_R13 = decrypted_instruction.find('004d', ptr_mv_R12)
        if count_down == 0:
            break
        if address in anti_loop_address:
            count_down = count_down - 1
        anti_loop_address.append(address)
        #deobfucate.append(decrypted_instruction[:ptr_mv_R12] + decrypted_instruction[ptr_mv_R12+8:ptr_br_R13])
        deobfucate.append(decrypted_instruction[:])
        print('[decrypt instruction]  -- {}:{}'.format(address, deobfucate[-1]))
        address = register.swap_byte(decrypted_instruction[ptr_mv_R12+4:ptr_mv_R12+8])
        address = hex(int(address, 16) - 0x3194)[2:6]

    return deobfucate
class string_manipulator:
    @staticmethod    
    def string_to_hex(string):
        return ''.join(x.encode('hex') for x in string)

    @staticmethod    
    def gen_string(size = 12):
        gened_string = ''
        for i in range(size):
            gened_string = gened_string + random.choice(STRING.hexdigits)

        return gened_string

def test_string(hex_string):
    R6 = '0000'
    R4 = '0000'
    reg_sim = register()
    while hex_string != '' :
        R4 =reg_sim.add_registers(register.read_mem(hex_string, 0), R4)
        R4 = register.swap_byte(R4)
        R6 = register.xor_registers(register.read_mem(hex_string, 0), R6)
        R6 = register.xor_registers(R4, R6)
        R4 = register.xor_registers(R6, R4)
        R6 = register.xor_registers(R4, R6)
        print('[debug info test string {}] R4:{}, R6:{}'.format(hex_string, R4, R6))
        hex_string = hex_string[4:]
    if R4 == 'feb1' and R6 == '9298':
        print("found string:{} ".format(hex_string))
        return True
    return False

def holywood_solver():
    string = ''
    while(not test_string(string)):
        string =  string_manipulator.gen_string(12)
    print('found string {}'.format(string))
