[Variables]

;---- CPU Sensors and Values----

CPUName						=%1

CPU_RLLeft_MaxValue			=95				
CPU_RLLeft_MinValue			=0
CPU_RLRight_MaxValue		=100				
CPU_RLRight_MinValue		=0

CPU-LeftRL_Id				=0xf0000501
CPU-LeftRL_Instance			=0x0
CPU-LeftRL_EntryId			=0x1000003

CPU-RightRL_ID				=0xf0000300
CPU-RightRL_Instance		=0x0
CPU-RightRL_EntryId			=0x7000019

CPU-Usage-Total_ID			=0xf0000300
CPU-Usage-Total_Instance	=0x0
CPU-Usage-Total_EntryId		=0x7000019

CPU-Temp_Id					=0xf0000501
CPU-Temp_Instance			=0x0
CPU-Temp_EntryId			=0x1000003

CPU-FAN1_ID					=0xf7067980
CPU-FAN1_Instance			=0x0
CPU-FAN1_EntryId			=0x3000001

CPU-FAN2_ID					=
CPU-FAN2_Instance			=
CPU-FAN2_EntryId			=

CPU-VCore_Id				=0xf0000501
CPU-VCore_Instance			=0x0
CPU-VCore_EntryId			=0x2000000

CPU-PackagePwr_ID			=0xf0000501
CPU-PackagePwr_Instance		=0x0
CPU-PackagePwr_EntryId		=0x500000d

CPUA-Clock_ID				=0xf0000300
CPUA-Clock_Instance			=0x0
CPUA-Clock_EntryId			=0x6000000

CPUB-Clock_ID				=0xf0000300
CPUB-Clock_Instance			=0x0
CPUB-Clock_EntryId			=0x6000004

CPUC-Clock_ID				=0xf0000300
CPUC-Clock_Instance			=0x0
CPUC-Clock_EntryId			=0x6000008

CPUD-Clock_ID				=0xf0000300
CPUD-Clock_Instance			=0x0
CPUD-Clock_EntryId			=0x600000b


;---- CPU 2 Sensors and Values----

CPU2Name					=%1

CPU2_RLLeft_MaxValue		=105				
CPU2_RLLeft_MinValue		=25
CPU2_RLRight_MaxValue		=100				
CPU2_RLRight_MinValue		=0

CPU2-LeftRL_Id				=0xf0000501
CPU2-LeftRL_Instance		=0x0
CPU2-LeftRL_EntryId			=0x1000004

CPU2-RightRL_ID				=0xf0000300
CPU2-RightRL_Instance		=0x0
CPU2-RightRL_EntryId		=0x7000011

CPU2-Usage-Total_ID			=0xf0000300
CPU2-Usage-Total_Instance	=0x0
CPU2-Usage-Total_EntryId	=0x7000011

CPU2-Temp_Id				=0xf0000501
CPU2-Temp_Instance			=0x0
CPU2-Temp_EntryId			=0x1000004

CPU2-FAN1_ID				=0xf0000501
CPU2-FAN1_Instance			=0x0
CPU2-FAN1_EntryId			=0x4000000

CPU2-FAN2_ID				=
CPU2-FAN2_Instance			=
CPU2-FAN2_EntryId			=

CPU2-VCore_Id				=0xf0000501
CPU2-VCore_Instance			=0x0
CPU2-VCore_EntryId			=0x2000000

CPU2-PackagePwr_ID			=0xf0000501
CPU2-PackagePwr_Instance	=0x0
CPU2-PackagePwr_EntryId		=0x500000b

CPU2A-Clock_ID				=0xf0000300
CPU2A-Clock_Instance		=0x0
CPU2A-Clock_EntryId			=0x6000000

CPU2B-Clock_ID				=0xf0000300
CPU2B-Clock_Instance		=0x0
CPU2B-Clock_EntryId			=0x6000001

CPU2C-Clock_ID				=0xf0000300
CPU2C-Clock_Instance		=0x0
CPU2C-Clock_EntryId			=0x6000002

CPU2D-Clock_ID				=0xf0000300
CPU2D-Clock_Instance		=0x0
CPU2D-Clock_EntryId			=0x6000003

CPU2E-Clock_ID				=0xf0000300
CPU2E-Clock_Instance		=0x0
CPU2E-Clock_EntryId			=0x6000004

CPU2F-Clock_ID				=0xf0000300
CPU2F-Clock_Instance		=0x0
CPU2F-Clock_EntryId			=0x6000005

CPU2G-Clock_ID				=0xf0000300
CPU2G-Clock_Instance		=0x0
CPU2G-Clock_EntryId			=0x6000006

CPU2H-Clock_ID				=0xf0000300
CPU2H-Clock_Instance		=0x0
CPU2H-Clock_EntryId			=0x6000007


;---- GPU FPS with Rivatuner Statistics Server----
GPU-FPS_Id					=[Input4a-Field]
GPU-FPS_Instance			=[Input4b-Field]
GPU-FPS_EntryId				=[Input4c-Field]


;---- GPU Sensors and Values----

GPUName						=Radeon Vega

GPU_RLLeft_MaxValue			=105				
GPU_RLLeft_MinValue			=25
GPU_RLRight_MaxValue		=100				
GPU_RLRight_MinValue		=0

GPU-LeftRL_Id				=0xe0001800
GPU-LeftRL_Instance			=0x20
GPU-LeftRL_EntryId			=0x1000000

GPU-RightRL_ID				=0xe0001800
GPU-RightRL_Instance		=0x20
GPU-RightRL_EntryId			=0x7000000

GPU-CoreLoad_Id				=0xe0001800
GPU-CoreLoad_Instance		=0x20
GPU-CoreLoad_EntryId		=0x7000000

GPU-Temp_Id					=0xe0001800
GPU-Temp_Instance			=0x20
GPU-Temp_EntryId			=0x1000000

GPU-FAN1_Id					=0xe0001800
GPU-FAN1_Instance			=0x20
GPU-FAN1_EntryId			=0x2000000

GPU-FAN2_Id					=
GPU-FAN2_Instance			=
GPU-FAN2_EntryId			=

GPU-VRAM_Id					=0xe0001800
GPU-VRAM_Instance			=0x20
GPU-VRAM_EntryId			=0x8000001

GPU-Power_Id				=0xe0001800
GPU-Power_Instance			=0x20
GPU-Power_EntryId			=0x5000001

GPU-Clock_Id				=0xe0001800
GPU-Clock_Instance			=0x20
GPU-Clock_EntryId			=0x6000000

;---- GPU2 Sensors and Values----

GPU2Name					=%1

GPU2_RLLeft_MaxValue		=105				
GPU2_RLLeft_MinValue		=25
GPU2_RLRight_MaxValue		=100				
GPU2_RLRight_MinValue		=0

GPU2-LeftRL_Id				=0xe0002000
GPU2-LeftRL_Instance		=0x0
GPU2-LeftRL_EntryId			=0x1000000

GPU2-RightRL_ID				=0xe0002000
GPU2-RightRL_Instance		=0x0
GPU2-RightRL_EntryId		=0x7000000

GPU2-CoreLoad_Id			=0xe0002000
GPU2-CoreLoad_Instance		=0x0
GPU2-CoreLoad_EntryId		=0x7000000

GPU2-Temp_Id				=0xe0002000
GPU2-Temp_Instance			=0x0
GPU2-Temp_EntryId			=0x1000000

GPU2-FAN1_Id				=0xe0002000
GPU2-FAN1_Instance			=0x0
GPU2-FAN1_EntryId			=0x2000000

GPU2-FAN2_Id				=
GPU2-FAN2_Instance			=
GPU2-FAN2_EntryId			=

GPU2-VRAM_Id				=0xe0002000
GPU2-VRAM_Instance			=0x0
GPU2-VRAM_EntryId			=0x80000fc

GPU2-Power_Id				=0xe0002000
GPU2-Power_Instance			=0x0
GPU2-Power_EntryId			=0x5000000

GPU2-Clock_Id				=0xe0002000
GPU2-Clock_Instance			=0x0
GPU2-Clock_EntryId			=0x6000000


;---- Mainboard Sensors and Values----

MainboardName				=%1

Mainboard_RLLeft_MaxValue	=95				
Mainboard_RLLeft_MinValue	=0
Mainboard_RLRight_MaxValue0	=1500				
Mainboard_RLRight_MinValue0	=500
Mainboard_RLRight_MaxValue1	=8200				
Mainboard_RLRight_MinValue1	=3000

Mainboard-LeftRL_Id			=0xf0ec0502
Mainboard-LeftRL_Instance	=0x0
Mainboard-LeftRL_EntryId	=0x1000001

Mainboard-RightRL_ID0		=0xf0008665
Mainboard-RightRL_Instance0	=0x0
Mainboard-RightRL_EntryId0	=0x3000001

Mainboard-RightRL_ID1		=All-FANs
Mainboard-RightRL_Instance1	=All-FANs
Mainboard-RightRL_EntryId1	=All-FANs

MB-Temp_Id					=0xf0008665
MB-Temp_Instance			=0x0
MB-Temp_EntryId				=0x1000001

MB-Sensor-Temp_Id			=0xf0ec0502
MB-Sensor-Temp_Instance		=0x0
MB-Sensor-Temp_EntryId		=0x1000002

MB-PCH-Temp_Id				=0xf0ec0502
MB-PCH-Temp_Instance		=0x0
MB-PCH-Temp_EntryId			=0x1000001

MB-FAN1_Id					=0xf0008665
MB-FAN1_Instance			=0x0
MB-FAN1_EntryId				=0x3000000

MB-FAN2_Id					=0xf0008665
MB-FAN2_Instance			=0x0
MB-FAN2_EntryId				=0x3000000

MB-FAN3_Id					=0xf0ec0502
MB-FAN3_Instance			=0x0
MB-FAN3_EntryId				=0x3000000

MB-FAN4_Id					=0xf0008665
MB-FAN4_Instance			=0x0
MB-FAN4_EntryId				=0x3000001


;---- Mainboard Sensors and Values----

LiquidName					=H2O Cooler

Liquid_RLLeft_MaxValue		=60				
Liquid_RLLeft_MinValue		=0
Liquid_RLRight_MaxValue		=4500				
Liquid_RLRight_MinValue		=2000

Liquid-Sensor-Temp_Id		=0xf0ec0502
Liquid-Sensor-Temp_Instance	=0x0
Liquid-Sensor-Temp_EntryId	=0x1000002

Liquid-Sensor-Pump_Id		=0xf0008665
Liquid-Sensor-Pump_Instance	=0x0
Liquid-Sensor-Pump_EntryId	=0x3000005

Liquid-FAN1_Id				=0xf0008665
Liquid-FAN1_Instance		=0x0
Liquid-FAN1_EntryId			=0x3000000

Liquid-FAN2_Id				=0xf0008665
Liquid-FAN2_Instance		=0x0
Liquid-FAN2_EntryId			=0x3000000

Liquid-FAN3_Id				=0xf0ec0502
Liquid-FAN3_Instance		=0x0
Liquid-FAN3_EntryId			=0x3000000


;---- RAM Sensors and Values ----

RAMName						=DDR4-%1

DRAM-Clock_ID				=0xf0000301
DRAM-Clock_Instance			=0x1
DRAM-Clock_EntryId			=0x6000000

DRAM-TCAS_ID				=0xf0000301
DRAM-TCAS_Instance			=0x1
DRAM-TCAS_EntryId			=0x8000001

DRAM-TRCD_ID				=0xf0000301
DRAM-TRCD_Instance			=0x1
DRAM-TRCD_EntryId			=0x8000002

DRAM-TRP_ID					=0xf0000301
DRAM-TRP_Instance			=0x1
DRAM-TRP_EntryId			=0x8000003

DRAM-TRAS_ID				=0xf0000301
DRAM-TRAS_Instance			=0x1
DRAM-TRAS_EntryId			=0x8000004

DRAM-TRC_ID					=0xf0000301
DRAM-TRC_Instance			=0x1
DRAM-TRC_EntryId			=0x8000005

DRAM-Temp_ID				=
DRAM-Temp_Instance			=
DRAM-Temp_EntryId			=


;- Drive1 Sensor Readings ------------

Drive1Name					=%1

Drive1_RLLeft_MaxValue		=80				
Drive1_RLLeft_MinValue		=30
Drive1_RLRight_MaxValue		=100				
Drive1_RLRight_MinValue		=0

Drive1-LeftRL_Id			=0xf0000100
Drive1-LeftRL_Instance		=0x2
Drive1-LeftRL_EntryId		=0x1000000

Drive1-RightRL_ID			=0xf0000101
Drive1-RightRL_Instance		=0x2
Drive1-RightRL_EntryId		=0x7000002

Drive1-Temp_Id				=0xf0000100
Drive1-Temp_Instance		=0x2
Drive1-Temp_EntryId			=0x1000000

Drive1-TotalActivity_Id		=0xf0000101
Drive1-TotalActivity_Instance=0x2
Drive1-TotalActivity_EntryId=0x7000002

Drive1-ReadRate_Id			=0xf0000101
Drive1-ReadRate_Instance	=0x2
Drive1-ReadRate_EntryId		=0x8000000

Drive1-WriteRate_Id			=0xf0000101
Drive1-WriteRate_Instance	=0x2
Drive1-WriteRate_EntryId	=0x8000001


;- Drive2 Sensor Readings ------------

Drive2Name					=%1

Drive2_RLLeft_MaxValue		=80				
Drive2_RLLeft_MinValue		=20
Drive2_RLRight_MaxValue		=100				
Drive2_RLRight_MinValue		=0

Drive2-LeftRL_Id			=0xf0000100
Drive2-LeftRL_Instance		=0x1
Drive2-LeftRL_EntryId		=0x1000000

Drive2-RightRL_ID			=0xf0000101
Drive2-RightRL_Instance		=0x1
Drive2-RightRL_EntryId		=0x7000002

Drive2-Temp_Id				=0xf0000100
Drive2-Temp_Instance		=0x1
Drive2-Temp_EntryId			=0x1000000

Drive2-TotalActivity_Id		=0xf0000101
Drive2-TotalActivity_Instance=0x1
Drive2-TotalActivity_EntryId=0x7000002

Drive2-ReadRate_Id			=0xf0000101
Drive2-ReadRate_Instance	=0x1
Drive2-ReadRate_EntryId		=0x8000000

Drive2-WriteRate_Id			=0xf0000101
Drive2-WriteRate_Instance	=0x1
Drive2-WriteRate_EntryId	=0x8000001


;- Drive3 Sensor Readings ------------

Drive3Name					=%1

Drive3_RLLeft_MaxValue		=80				
Drive3_RLLeft_MinValue		=20
Drive3_RLRight_MaxValue		=100				
Drive3_RLRight_MinValue		=0

Drive3-LeftRL_Id			=0xf0000100
Drive3-LeftRL_Instance		=0x0
Drive3-LeftRL_EntryId		=0x1000000

Drive3-RightRL_ID			=0xf0000101
Drive3-RightRL_Instance		=0x0
Drive3-RightRL_EntryId		=0x7000002

Drive3-Temp_Id				=0xf0000100
Drive3-Temp_Instance		=0x0
Drive3-Temp_EntryId			=0x1000000

Drive3-TotalActivity_Id		=0xf0000101
Drive3-TotalActivity_Instance=0x0
Drive3-TotalActivity_EntryId=0x7000002

Drive3-ReadRate_Id			=0xf0000101
Drive3-ReadRate_Instance	=0x0
Drive3-ReadRate_EntryId		=0x8000000

Drive3-WriteRate_Id			=0xf0000101
Drive3-WriteRate_Instance	=0x0
Drive3-WriteRate_EntryId	=0x8000001


;- Drive4 Sensor Readings ------------

Drive4Name					=%1

Drive4_RLLeft_MaxValue		=80				
Drive4_RLLeft_MinValue		=0
Drive4_RLRight_MaxValue		=100				
Drive4_RLRight_MinValue		=0

Drive4-LeftRL_Id			=0xf0000100
Drive4-LeftRL_Instance		=0x1
Drive4-LeftRL_EntryId		=0x1000000

Drive4-RightRL_ID			=0xf0000101
Drive4-RightRL_Instance		=0x0
Drive4-RightRL_EntryId		=0x7000002

Drive4-Temp_Id				=0xf0000100
Drive4-Temp_Instance		=0x1
Drive4-Temp_EntryId			=0x1000000

Drive4-TotalActivity_Id		=0xf0000101
Drive4-TotalActivity_Instance=0x0
Drive4-TotalActivity_EntryId=0x7000002

Drive4-ReadRate_Id			=0xf0000101
Drive4-ReadRate_Instance	=0x0
Drive4-ReadRate_EntryId		=0x8000000

Drive4-WriteRate_Id			=0xf0000101
Drive4-WriteRate_Instance	=0x0
Drive4-WriteRate_EntryId	=0x8000001


;- Drive5 Sensor Readings ------------

Drive5Name					=%1

Drive5_RLLeft_MaxValue		=80				
Drive5_RLLeft_MinValue		=0
Drive5_RLRight_MaxValue		=100				
Drive5_RLRight_MinValue		=0

Drive5-LeftRL_Id			=0xf0000100
Drive5-LeftRL_Instance		=0x1
Drive5-LeftRL_EntryId		=0x1000000

Drive5-RightRL_ID			=0xf0000101
Drive5-RightRL_Instance		=0x0
Drive5-RightRL_EntryId		=0x7000002

Drive5-Temp_Id				=0xf0000100
Drive5-Temp_Instance		=0x1
Drive5-Temp_EntryId			=0x1000000

Drive5-TotalActivity_Id		=0xf0000101
Drive5-TotalActivity_Instance=0x0
Drive5-TotalActivity_EntryId=0x7000002

Drive5-ReadRate_Id			=0xf0000101
Drive5-ReadRate_Instance	=0x0
Drive5-ReadRate_EntryId		=0x8000000

Drive5-WriteRate_Id			=0xf0000101
Drive5-WriteRate_Instance	=0x0
Drive5-WriteRate_EntryId	=0x8000001


;- Drive6 Sensor Readings ------------

Drive6Name					=%1

Drive6_RLLeft_MaxValue		=80				
Drive6_RLLeft_MinValue		=0
Drive6_RLRight_MaxValue		=100				
Drive6_RLRight_MinValue		=0

Drive6-LeftRL_Id			=0xf0000100
Drive6-LeftRL_Instance		=0x1
Drive6-LeftRL_EntryId		=0x1000000

Drive6-RightRL_ID			=0xf0000101
Drive6-RightRL_Instance		=0x0
Drive6-RightRL_EntryId		=0x7000002

Drive6-Temp_Id				=0xf0000100
Drive6-Temp_Instance		=0x1
Drive6-Temp_EntryId			=0x1000000

Drive6-TotalActivity_Id		=0xf0000101
Drive6-TotalActivity_Instance=0x0
Drive6-TotalActivity_EntryId=0x7000002

Drive6-ReadRate_Id			=0xf0000101
Drive6-ReadRate_Instance	=0x0
Drive6-ReadRate_EntryId		=0x8000000

Drive6-WriteRate_Id			=0xf0000101
Drive6-WriteRate_Instance	=0x0
Drive6-WriteRate_EntryId	=0x8000001


;- Drive7 Sensor Readings ------------

Drive7Name					=%1

Drive7_RLLeft_MaxValue		=80				
Drive7_RLLeft_MinValue		=0
Drive7_RLRight_MaxValue		=100				
Drive7_RLRight_MinValue		=0

Drive7-LeftRL_Id			=0xf0000100
Drive7-LeftRL_Instance		=0x1
Drive7-LeftRL_EntryId		=0x1000000

Drive7-RightRL_ID			=0xf0000101
Drive7-RightRL_Instance		=0x0
Drive7-RightRL_EntryId		=0x7000002

Drive7-Temp_Id				=0xf0000100
Drive7-Temp_Instance		=0x1
Drive7-Temp_EntryId			=0x1000000

Drive7-TotalActivity_Id		=0xf0000101
Drive7-TotalActivity_Instance=0x0
Drive7-TotalActivity_EntryId=0x7000002

Drive7-ReadRate_Id			=0xf0000101
Drive7-ReadRate_Instance	=0x0
Drive7-ReadRate_EntryId		=0x8000000

Drive7-WriteRate_Id			=0xf0000101
Drive7-WriteRate_Instance	=0x0
Drive7-WriteRate_EntryId	=0x8000001


;- Drive8 Sensor Readings ------------

Drive8Name					=%1

Drive8_RLLeft_MaxValue		=80				
Drive8_RLLeft_MinValue		=0
Drive8_RLRight_MaxValue		=100				
Drive8_RLRight_MinValue		=0

Drive8-LeftRL_Id			=0xf0000100
Drive8-LeftRL_Instance		=0x1
Drive8-LeftRL_EntryId		=0x1000000

Drive8-RightRL_ID			=0xf0000101
Drive8-RightRL_Instance		=0x0
Drive8-RightRL_EntryId		=0x7000002

Drive8-Temp_Id				=0xf0000100
Drive8-Temp_Instance		=0x1
Drive8-Temp_EntryId			=0x1000000

Drive8-TotalActivity_Id		=0xf0000101
Drive8-TotalActivity_Instance=0x0
Drive8-TotalActivity_EntryId=0x7000002

Drive8-ReadRate_Id			=0xf0000101
Drive8-ReadRate_Instance	=0x0
Drive8-ReadRate_EntryId		=0x8000000

Drive8-WriteRate_Id			=0xf0000101
Drive8-WriteRate_Instance	=0x0
Drive8-WriteRate_EntryId	=0x8000001

