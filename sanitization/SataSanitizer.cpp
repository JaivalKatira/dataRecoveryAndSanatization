#include "SataSanitizer.h"

#include <scsi/sg.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <string>

#include <cerrno>
#include <cstring>

namespace core::sanitization{

// ============================================================
// ATA CAPABILITIES
// ============================================================

// Stores the capabilities reported by the SATA device.
struct AtaCapabilities{

// ATA Sanitize Device feature set supported.
bool sanitizeSupported=false;

// Device supports Crypto Scramble EXT.
bool cryptoScrambleSupported=false;

// Device supports Block Erase EXT.
bool blockEraseSupported=false;

// Device supports Overwrite EXT.
bool overwriteSupported=false;

// ATA Security feature set information.
bool securitySupported=false;
bool securityEnabled=false;
bool securityFrozen=false;
bool enhancedSecurityEraseSupported=false;
};


// ============================================================
// SATA SANITIZATION METHOD
// ============================================================

// Represents the sanitization method selected for the drive.
struct SataMethod{

enum class Type{

// No supported method found.
NONE,

// ATA Sanitize using Crypto Scramble.
SANITIZE_CRYPTO,

// ATA Sanitize using Block Erase.
SANITIZE_BLOCK,

// ATA Sanitize using Overwrite.
SANITIZE_OVERWRITE
};

// Selected method.
Type type=Type::NONE;

// ATA FEATURE register value.
uint8_t featureCode=0x00;

// Human-readable method name.
std::string name;
};


// ============================================================
// ATA COMMAND RESULT
// ============================================================

// Contains the result returned by an ATA pass-through command.
struct AtaCommandResult{

// True when SG_IO reports successful execution.
bool success=false;

// SCSI status returned by the transport layer.
uint8_t scsiStatus=0;

// Host adapter status.
uint16_t hostStatus=0;

// Linux SCSI driver status.
uint16_t driverStatus=0;

// Sense data returned by the device.
std::array<uint8_t,32> senseData{};

// ATA status register.
uint8_t ataStatus=0;

// ATA error register.
uint8_t ataError=0;
};

struct AtaSanitizeStatus{
bool valid=false;
bool operationInProgress=false;
bool completedSuccessfully=false;
bool frozen=false;
bool failed=false;
uint16_t progress=0xFFFF;
uint8_t ataStatus=0;
uint8_t ataError=0;
};

// ============================================================
// LOW-LEVEL ATA PASS-THROUGH
// ============================================================
void decodeAtaError(const AtaCommandResult&result);
// Sends an ATA command through Linux SG_IO/SAT.
AtaCommandResult executeAtaPassthrough(
int fd,
uint8_t* cdb,
uint8_t cdbLength,
uint8_t* data,
uint32_t dataLength,
int direction,
uint32_t timeoutMs
){

AtaCommandResult result;

// Linux SCSI generic I/O structure.
sg_io_hdr_t io_hdr{};

// Identify this as an SG_IO request.
io_hdr.interface_id='S';

// Length of the SCSI CDB.
io_hdr.cmd_len=cdbLength;

// Maximum amount of sense data to receive.
io_hdr.mx_sb_len=result.senseData.size();

// Direction of data transfer.
io_hdr.dxfer_direction=direction;

// Number of bytes transferred.
io_hdr.dxfer_len=dataLength;

// Buffer for transferred data.
io_hdr.dxferp=data;

// ATA PASS-THROUGH CDB.
io_hdr.cmdp=cdb;

// Buffer for SCSI sense data.
io_hdr.sbp=result.senseData.data();

// Command timeout in milliseconds.
io_hdr.timeout=timeoutMs;

// Send command to the device.
if(ioctl(fd,SG_IO,&io_hdr)<0){

std::cerr
<<"SG_IO ioctl failed\n";

return result;
}

// Save transport status information.
result.scsiStatus=io_hdr.status;
result.hostStatus=io_hdr.host_status;
result.driverStatus=io_hdr.driver_status;

// SG_INFO_OK means the command completed successfully.
if((io_hdr.info&SG_INFO_OK_MASK)!=SG_INFO_OK){

std::cerr<<"ATA command failed\n";

std::cerr
<<"SCSI status: 0x"
<<std::hex
<<static_cast<int>(result.scsiStatus)
<<"\n";

std::cerr
<<"Host status: 0x"
<<result.hostStatus
<<"\n";

std::cerr
<<"Driver status: 0x"
<<result.driverStatus
<<std::dec
<<"\n";

// Decode device-provided sense information.
decodeAtaError(result);

return result;
}

// Command completed successfully.
result.success=true;

return result;
}

// ============================================================
// ATA/SCSI SENSE DECODER
// ============================================================

// Decodes the SCSI sense information returned by ATA PASS-THROUGH.
void decodeAtaError(const AtaCommandResult& result){
const auto&s=result.senseData;

// No sense data available.
if(s[0]==0){
std::cerr<<"No sense data available.\n";
return;
}

// Sense response format.
uint8_t responseCode=s[0]&0x7F;

std::cerr
<<"Sense response code: 0x"
<<std::hex
<<static_cast<int>(responseCode)
<<std::dec
<<"\n";

// Fixed-format sense data.
if(responseCode==0x70||responseCode==0x71){

// Sense key is stored in the low 4 bits of byte 2.
uint8_t senseKey=s[2]&0x0F;

// Additional Sense Code.
uint8_t asc=s[12];

// Additional Sense Code Qualifier.
uint8_t ascq=s[13];

std::cerr
<<"Sense key: 0x"
<<std::hex
<<static_cast<int>(senseKey)
<<std::dec
<<"\n";

std::cerr
<<"ASC: 0x"
<<std::hex
<<static_cast<int>(asc)
<<"\n";

std::cerr
<<"ASCQ: 0x"
<<static_cast<int>(ascq)
<<std::dec
<<"\n";

// Human-readable sense-key description.
switch(senseKey){

case 0x0:
std::cerr<<"Sense: No Sense\n";
break;

case 0x1:
std::cerr<<"Sense: Recovered Error\n";
break;

case 0x2:
std::cerr<<"Sense: Not Ready\n";
break;

case 0x3:
std::cerr<<"Sense: Medium Error\n";
break;

case 0x4:
std::cerr<<"Sense: Hardware Error\n";
break;

case 0x5:
std::cerr<<"Sense: Illegal Request\n";
break;

case 0x6:
std::cerr<<"Sense: Unit Attention\n";
break;

case 0x7:
std::cerr<<"Sense: Data Protect\n";
break;

case 0x8:
std::cerr<<"Sense: Blank Check\n";
break;

case 0xB:
std::cerr<<"Sense: Aborted Command\n";
break;

case 0xD:
std::cerr<<"Sense: Volume Overflow\n";
break;

case 0xE:
std::cerr<<"Sense: Miscompare\n";
break;

default:
std::cerr<<"Sense: Unknown\n";
break;
}

return;
}

std::cerr
<<"Unsupported sense-data format.\n";
}

bool parseAtaReturnDescriptor(
const std::array<uint8_t,32>&sense,
AtaSanitizeStatus&status
){
if(sense[0]!=0x72&&sense[0]!=0x73){
return false;
}

const uint8_t additionalLength=sense[7];

if(additionalLength<14){
return false;
}

for(std::size_t i=8;i+1<32;){
uint8_t descriptorCode=sense[i];
uint8_t descriptorLength=sense[i+1];

if(descriptorLength==0){
return false;
}

if(i+2+descriptorLength>32){
return false;
}

if(descriptorCode==0x09){
if(descriptorLength<0x0C){
return false;
}

//const uint8_t extend=sense[i+2]&0x01;

status.ataError=sense[i+3];

const uint16_t sectorCount=
static_cast<uint16_t>(
(static_cast<uint16_t>(sense[i+4])<<8)|
sense[i+5]
);

const uint8_t ataStatus=sense[i+13];

status.ataStatus=ataStatus;

status.completedSuccessfully=
(sectorCount&(1u<<15))!=0;

status.operationInProgress=
(sectorCount&(1u<<14))!=0;

status.frozen=
(sectorCount&(1u<<13))!=0;

if(status.operationInProgress){
status.progress=
static_cast<uint16_t>(
(static_cast<uint16_t>(sense[i+8])<<8)|
sense[i+9]
);
}else{
status.progress=0xFFFF;
}

status.valid=true;
return true;
}

i+=2+descriptorLength;
}

return false;
}


bool getSanitizeStatus(
int fd,
AtaSanitizeStatus&status
){
std::array<uint8_t,16> cdb{};

cdb[0]=0x85;

// ATA PASS-THROUGH(16)
// Protocol = 15: Return Response Information
cdb[1]=(15<<1);

// CK_COND = 1
cdb[2]=(1<<5);

// Feature = 0x0000
cdb[3]=0x00;
cdb[4]=0x00;

// Sector Count = 0
cdb[5]=0x00;
cdb[6]=0x00;

// LBA = 0
cdb[7]=0x00;
cdb[8]=0x00;
cdb[9]=0x00;
cdb[10]=0x00;
cdb[11]=0x00;
cdb[12]=0x00;

// Device
cdb[13]=0x00;

// SANITIZE DEVICE
cdb[14]=0xB4;

// Control
cdb[15]=0x00;

sg_io_hdr_t io_hdr{};

io_hdr.interface_id='S';
io_hdr.cmd_len=16;
io_hdr.mx_sb_len=32;
io_hdr.dxfer_direction=SG_DXFER_NONE;
io_hdr.dxfer_len=0;
io_hdr.dxferp=nullptr;
io_hdr.cmdp=cdb.data();

std::array<uint8_t,32>sense{};
io_hdr.sbp=sense.data();
io_hdr.mx_sb_len=sense.size();
io_hdr.timeout=20000;

if(ioctl(fd,SG_IO,&io_hdr)<0){
std::cerr<<"SANITIZE STATUS SG_IO failed\n";
return false;
}

if(!parseAtaReturnDescriptor(sense,status)){
std::cerr<<"ATA Status Return Descriptor not found\n";

std::cerr<<"Sense data:";
for(uint8_t b:sense){
std::cerr<<" "<<std::hex
<<static_cast<int>(b);
}
std::cerr<<std::dec<<"\n";

return false;
}

return true;
}

void printSanitizeStatus(const AtaSanitizeStatus&status){
if(!status.valid){
std::cout<<"\nSanitize status: Invalid\n";
return;
}

std::cout<<"\nSanitize status:\n";

if(status.frozen){
std::cout<<"State: Frozen\n";
return;
}

if(status.operationInProgress){
double percent=
(static_cast<double>(status.progress)*100.0)/65536.0;

std::cout<<"State: In Progress\n";
std::cout<<"Progress: "<<percent<<"%\n";
return;
}

if(status.completedSuccessfully){
std::cout<<"State: Completed Successfully\n";
return;
}

std::cout<<"State: Idle\n";
}
// ============================================================
// ATA IDENTIFY DEVICE
// ============================================================

// Reads the 512-byte ATA IDENTIFY DEVICE response.
bool identifyAtaDevice(
int fd,
std::array<uint8_t,512>& data
){

// 16-byte ATA PASS-THROUGH(16) CDB.
uint8_t cdb[16]={};

// ATA PASS-THROUGH(16) opcode.
cdb[0]=0x85;

// Protocol 4 = PIO Data-In.
cdb[1]=(4<<1);

/*
 * ATA PASS-THROUGH flags:
 *
 * T_LENGTH = 2
 * BYTE_BLOCK = 1
 * T_DIR = 1
 *
 * This indicates a block data transfer
 * from the device.
 */
cdb[2]=0x0E;

// ATA command register.
// 0xEC = IDENTIFY DEVICE.
cdb[14]=0xEC;

// Execute IDENTIFY DEVICE.
AtaCommandResult result=executeAtaPassthrough(
fd,
cdb,
sizeof(cdb),
data.data(),
data.size(),
SG_DXFER_FROM_DEV,
20000
);

return result.success;
}


// ============================================================
// ATA CAPABILITY DETECTION
// ============================================================

// Reads IDENTIFY DEVICE and extracts sanitization capabilities.
bool getAtaCapabilities(
int fd,
AtaCapabilities& caps
){

// Buffer for the 512-byte IDENTIFY response.
std::array<uint8_t,512> data{};

// Ask the drive for its IDENTIFY data.
if(!identifyAtaDevice(fd,data)){
return false;
}

// Convert an IDENTIFY byte pair into a 16-bit ATA word.
auto getWord=[&](std::size_t word)->uint16_t{

std::size_t offset=word*2;

return static_cast<uint16_t>(
data[offset]|
(static_cast<uint16_t>(data[offset+1])<<8)
);
};

// IDENTIFY DEVICE word 59.
const uint16_t word59=getWord(59);

// --------------------------------------------------------
// ATA SANITIZE CAPABILITIES
// --------------------------------------------------------

/*
 * Sanitize capability bits are stored in word 59.
 *
 * Bit 12 = Sanitize Device supported
 * Bit 13 = Crypto Scramble EXT supported
 * Bit 14 = Overwrite EXT supported
 * Bit 15 = Block Erase EXT supported
 *
 * These values are used only for capability detection.
 */

caps.sanitizeSupported=
(word59&(1u<<12))!=0;

caps.cryptoScrambleSupported=
(word59&(1u<<13))!=0;

caps.overwriteSupported=
(word59&(1u<<14))!=0;

caps.blockEraseSupported=
(word59&(1u<<15))!=0;


// --------------------------------------------------------
// ATA SECURITY CAPABILITIES
// --------------------------------------------------------

// IDENTIFY DEVICE word 128.
const uint16_t word128=getWord(128);

/*
 * ATA Security bits:
 *
 * Bit 0 = Security supported
 * Bit 1 = Security enabled
 * Bit 3 = Security frozen
 * Bit 5 = Enhanced Security Erase supported
 */

caps.securitySupported=
(word128&(1u<<0))!=0;

caps.securityEnabled=
(word128&(1u<<1))!=0;

caps.securityFrozen=
(word128&(1u<<3))!=0;

caps.enhancedSecurityEraseSupported=
(word128&(1u<<5))!=0;

return true;
}


// ============================================================
// METHOD SELECTION
// ============================================================

// Chooses the preferred ATA Sanitize method.
SataMethod determineSataMethod(
const AtaCapabilities& caps
){

SataMethod method;

// No ATA Sanitize support.
if(!caps.sanitizeSupported){
return method;
}

/*
 * Preferred order:
 *
 * 1. Crypto Scramble
 * 2. Block Erase
 * 3. Overwrite
 *
 * The actual policy can later be made configurable.
 */

if(caps.cryptoScrambleSupported){

method.type=
SataMethod::Type::SANITIZE_CRYPTO;

method.featureCode=0x11;

method.name=
"ATA Sanitize (Crypto Scramble)";

return method;
}

if(caps.blockEraseSupported){

method.type=
SataMethod::Type::SANITIZE_BLOCK;

method.featureCode=0x12;

method.name=
"ATA Sanitize (Block Erase)";

return method;
}

if(caps.overwriteSupported){

method.type=
SataMethod::Type::SANITIZE_OVERWRITE;

method.featureCode=0x14;

method.name=
"ATA Sanitize (Overwrite)";

return method;
}

return method;
}


// ============================================================
// BUILD ATA SANITIZE COMMAND
// ============================================================

// Constructs the ATA SANITIZE DEVICE command.
// IMPORTANT: This function only builds the command.
// It does NOT send the command to the drive.
std::array<uint8_t,16> buildSanitizeCommand(
const SataMethod& method
){

// 16-byte ATA PASS-THROUGH CDB.
std::array<uint8_t,16> cdb{};

// ATA PASS-THROUGH(16).
cdb[0]=0x85;

// Protocol 3 = Non-data.
cdb[1]=(3<<1);

// ATA PASS-THROUGH flags for a non-data command.
cdb[2]=0x20;

// FEATURE register.
// Contains the selected SANITIZE DEVICE feature.
cdb[3]=method.featureCode;

// ATA command register.
// 0xB4 = SANITIZE DEVICE.
cdb[14]=0xB4;

return cdb;
}


// ============================================================
// PRINT CAPABILITIES
// ============================================================

// Displays detected ATA capabilities.
void printCapabilities(
const AtaCapabilities& caps
){

std::cout
<<"\nATA capabilities:\n";

std::cout
<<"Sanitize Supported: "
<<(caps.sanitizeSupported?"Yes":"No")
<<"\n";

std::cout
<<"Crypto Scramble: "
<<(caps.cryptoScrambleSupported?"Yes":"No")
<<"\n";

std::cout
<<"Block Erase: "
<<(caps.blockEraseSupported?"Yes":"No")
<<"\n";

std::cout
<<"Overwrite: "
<<(caps.overwriteSupported?"Yes":"No")
<<"\n";

std::cout
<<"Security Supported: "
<<(caps.securitySupported?"Yes":"No")
<<"\n";

std::cout
<<"Security Enabled: "
<<(caps.securityEnabled?"Yes":"No")
<<"\n";

std::cout
<<"Security Frozen: "
<<(caps.securityFrozen?"Yes":"No")
<<"\n";

std::cout
<<"Enhanced Security Erase: "
<<(caps.enhancedSecurityEraseSupported?"Yes":"No")
<<"\n";
}


// ============================================================
// SATA SANITIZER
// ============================================================

// Main SATA sanitization entry point.
bool SataSanitizer::wipe(
const core::drive::DriveInfo& drive
){

std::cout
<<"\n=== SATA Sanitizer ===\n";

std::cout
<<"Device: "
<<drive.devicePath
<<"\n";

std::cout
<<"Mode: DRY RUN\n";

/*
 * Open the block device.
 *
 * O_RDWR = allow ATA commands requiring read/write access.
 * O_EXCL = prevent simultaneous access where supported.
 */
int fd=open(drive.devicePath.c_str(),O_RDWR|O_EXCL);
if(fd<0){
std::cerr<<"Failed to open device: "<<drive.devicePath
         <<" ("<<errno<<": "<<std::strerror(errno)<<")\n";

if(errno==EBUSY){
std::cerr<<"Device is busy. One or more partitions may be mounted or in use.\n";
}

return false;
}

// --------------------------------------------------------
// CAPABILITY DETECTION
// --------------------------------------------------------

AtaCapabilities caps{};

if(!getAtaCapabilities(fd,caps)){

std::cerr
<<"IDENTIFY DEVICE failed\n";

close(fd);

return false;
}

// Display what the drive supports.
printCapabilities(caps);
AtaSanitizeStatus sanitizeStatus{};

if(getSanitizeStatus(fd,sanitizeStatus)){
printSanitizeStatus(sanitizeStatus);
}else{
std::cerr<<"Failed to read SANITIZE STATUS EXT\n";
}

// --------------------------------------------------------
// SECURITY STATE
// --------------------------------------------------------

/*
 * A frozen ATA Security state does not necessarily
 * prevent ATA Sanitize.
 *
 * We report it because it is useful diagnostic
 * information.
 */
if(caps.securityFrozen){

std::cout
<<"\nWARNING: ATA Security is frozen.\n";

std::cout
<<"This does not automatically mean ATA Sanitize is unavailable.\n";
}


// --------------------------------------------------------
// SELECT SANITIZATION METHOD
// --------------------------------------------------------

SataMethod method=
determineSataMethod(caps);

if(method.type==SataMethod::Type::NONE){

std::cerr
<<"\nNo supported ATA Sanitize method detected.\n";

close(fd);

return false;
}

std::cout
<<"\nSelected method: "
<<method.name
<<"\n";


// --------------------------------------------------------
// BUILD COMMAND
// --------------------------------------------------------

auto cdb=
buildSanitizeCommand(method);

std::cout
<<"\nSANITIZE DEVICE command:\n";

std::cout
<<"ATA opcode: 0x"
<<std::hex
<<static_cast<int>(cdb[14])
<<"\n";

std::cout
<<"Feature: 0x"
<<static_cast<int>(cdb[3])
<<std::dec
<<"\n";


// --------------------------------------------------------
// DRY RUN
// --------------------------------------------------------

/*
 * IMPORTANT:
 *
 * The command is intentionally NOT sent.
 *
 * ATA SANITIZE DEVICE is destructive.
 * We will only enable execution after:
 *
 * 1. Command/status handling is validated.
 * 2. Sense/error decoding is implemented.
 * 3. Completion polling is implemented.
 * 4. Testing is performed on a disposable drive.
 */

std::cout
<<"\n[DRY RUN]\n";

std::cout
<<"Command constructed successfully.\n";

std::cout
<<"No destructive ATA command was sent.\n";

close(fd);

/*
 * Returning false is intentional.
 *
 * A dry-run means no sanitization actually occurred.
 */
return false;
}

}