[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard Windows Measures ----

[Measure_MaxRAM]
Measure				=PhysicalMemory
Total				=1

[Measure_RAM0]
Measure				=PhysicalMemory

[Measure_RAM1]
Measure				=Calc
Formula				=Measure_MaxRAM-Measure_RAM0

[Measure_RAMPercentage0]
Measure				=Calc
Formula				=100-100*(Measure_RAM0/Measure_MaxRAM)
MaxValue			=100
MinValue			=0

[Measure_RAMPercentage1]
Measure				=Calc
Formula				=100*(Measure_RAM0/Measure_MaxRAM)
MaxValue			=100
MinValue			=0


;---- Standard HWiNFO Measures ----

[Measure_DRAMClock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#DRAM-Clock_Id#
HWiNFOSensorInstance=#DRAM-Clock_Instance#
HWiNFOEntryId		=#DRAM-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=-1

[Measure_DRAMTCAS]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#DRAM-TCAS_Id#
HWiNFOSensorInstance=#DRAM-TCAS_Instance#
HWiNFOEntryId		=#DRAM-TCAS_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=-1

[Measure_DRAMTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#DRAM-Temp_Id#
HWiNFOSensorInstance=#DRAM-Temp_Instance#
HWiNFOEntryId		=#DRAM-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1
IfCondition			=(Measure_DRAMTemp = 0)
IfTrueAction		=[!SetOption Info2Text Text "%1MHz-CL%2"]
IfFalseAction		=[!SetOption Info2Text Text "%1MHz | %3[\x00B0]#TempUnit#"]


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\DRAM#RAMColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\DRAM#RAMColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_RAM0
	MeasureName2=Measure_RAM1
	MeasureName3=Measure_RAMPercentage1
	MeasureName4=Measure_RAMPercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)

[Info2Text]
	Meter=String
	MeterStyle=PText | PSize5
	MeasureName=Measure_DRAMClock
	MeasureName2=Measure_DRAMTCAS
	MeasureName3=Measure_DRAMTemp
	Text=%1MHz-CL%2
	NumOfDecimals=0
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.19)


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#RAMShowPercentage#+#RAMShowFreeSpace#+#RAMShowRAMonly#
	UpdateRate=-1
	IfCondition=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1Text Text "%1B #VarUsed#"]
	IfCondition2=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1Text Text "%2B #VarFree#"]
	IfCondition3=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1Text Text "%3% #VarUsed#"]
	IfCondition4=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1Text Text "%4% #VarFree#"]
	DynamicVariables=1
	
	
;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure SpecialFunction Run]

[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
Parameter=perfmon/res

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size