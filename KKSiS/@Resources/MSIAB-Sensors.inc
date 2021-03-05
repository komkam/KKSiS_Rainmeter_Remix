[Variables]

;---- CPU Sensors and Values----

CPU_MSIAB_RLLeft_MaxValue	=95				
CPU_MSIAB_RLLeft_MinValue	=0
CPU_MSIAB_RLRight_MaxValue	=100				
CPU_MSIAB_RLRight_MinValue	=0
CPU_RLLeft_ID			=128
CPU_RLRight_ID			=144
CPU_RLLeft_DS			=CPU temperature
CPU_RLRight_DS			=CPU usage

SensorName128			=CPU Temperature
SensorUnit128			=[\x00B0]#TempUnit#
SensorName144			=CPU Usage
SensorUnit144			=%
SensorName160			=CPU Clock
SensorUnit160			=MHz
SensorName256			=CPU Power
SensorUnit256			=W


;---- GPU Sensors and Values----

GPUNameMSIAB			=%1

GPU_MSIAB_RLLeft_MaxValue	=95				
GPU_MSIAB_RLLeft_MinValue	=0
GPU_MSIAB_RLRight_MaxValue	=100				
GPU_MSIAB_RLRight_MinValue	=0
GPU_RLLeft_ID			=0
GPU_RLRight_ID			=48
GPU_RLLeft_DS			=GPU temperature
GPU_RLRight_DS			=GPU usage

SensorName0				=GPU Temperature
SensorUnit0				=[\x00B0]#TempUnit#
SensorName16			=GPU FAN1
SensorUnit16			=rpm
SensorName18			=GPU FAN2
SensorUnit18			=rpm
SensorName20			=GPU FAN3
SensorUnit20			=rpm
SensorName32			=GPU Core Clock
SensorUnit32			=MHz
SensorName34			=GPU VRAM Clock
SensorUnit34			=MHz
SensorName48			=GPU Usage
SensorUnit48			=%
SensorName49			=GPU VRAM Usage
SensorUnit49			=MB
SensorName64			=GPU Voltage
SensorUnit64			=V
SensorName96			=GPU Power
SensorUnit96			=W
SensorName112			=GPU Temp Limit
SensorUnit112			=[\x00B0]#TempUnit#
SensorName113			=GPU Power Limit
SensorUnit113			=W


;---- FPSView Sensors and Values ----

SensorName80			=Framerate
SensorUnit80			=FPS
SensorName81			=Frametime
SensorUnit81			=ms
SensorName82			=Framerate Min
SensorUnit82			=FPS
SensorName83			=Framerate Avg
SensorUnit83			=FPS
SensorName84			=Framerate Max
SensorUnit84			=FPS




;---- GPU2 Sensors and Values----

GPU2NameMSIAB			=%1 #2

GPU2_RLLeft_MaxValue	=95				
GPU2_RLLeft_MinValue	=0
GPU2_RLRight_MaxValue	=100				
GPU2_RLRight_MinValue	=0
GPU2_RLLeft_ID			=0
GPU2_RLRight_ID			=48

SensorName0				=GPU2 Temperature
SensorUnit0				=[\x00B0]#TempUnit#
SensorName16			=GPU2 FAN1
SensorUnit16			=rpm
SensorName18			=GPU2 FAN2
SensorUnit18			=rpm
SensorName20			=GPU2 FAN3
SensorUnit20			=rpm
SensorName32			=GPU2 Core Clock
SensorUnit32			=MHz
SensorName34			=GPU2 VRAM Clock
SensorUnit34			=MHz
SensorName48			=GPU2 Usage
SensorUnit48			=%
SensorName49			=GPU2 VRAM Usage
SensorUnit49			=MB
SensorName64			=GPU2 Voltage
SensorUnit64			=V
SensorName96			=GPU2 Power
SensorUnit96			=W
SensorName112			=GPU2 Temp Limit
SensorUnit112			=[\x00B0]#TempUnit#
SensorName113			=GPU2 Power Limit
SensorUnit113			=W
