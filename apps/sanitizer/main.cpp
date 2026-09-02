#include "../device/DriveManager.h"
#include "../../sanitization/SanitizationEngine.h"

#include <iostream>
#include <vector>

int main(){

std::cout<<"\n=====================================\n";
std::cout<<"        SIH SANITIZER TEST\n";
std::cout<<"=====================================\n";

core::drive::DriveManager manager;

auto drives=manager.getAvailableDrives();

if(drives.empty()){
std::cout<<"No drives detected.\n";
return 1;
}

for(std::size_t i=0;i<drives.size();++i){

const auto&drive=drives[i];

std::cout<<"\n["<<i<<"]\n";
std::cout<<"Device: "<<drive.devicePath<<"\n";
std::cout<<"Model: "<<drive.model<<"\n";
std::cout<<"Serial: "<<drive.serialNumber<<"\n";
std::cout<<"Bus: "<<drive.getBusTypeString()<<"\n";
std::cout<<"Capacity: "<<drive.capacityBytes<<" bytes\n";
std::cout<<"Media: "<<drive.getMediaTypeString()<<"\n";

}

std::cout<<"\nSelect drive index: ";

std::size_t index;

if(!(std::cin>>index)||index>=drives.size()){
std::cerr<<"Invalid drive selection.\n";
return 1;
}

const auto&drive=drives[index];

std::cout<<"\nSelected: "<<drive.devicePath<<"\n";
std::cout<<"Starting sanitization test...\n";

core::sanitization::SanitizationEngine engine;

bool result=engine.executeSanitization(drive);

if(result){
std::cout<<"\nSanitization completed.\n";
}else{
std::cout<<"\nSanitization did not execute.\n";
std::cout<<"This is expected while the sanitizer is in DRY RUN mode.\n";
}

return 0;
}