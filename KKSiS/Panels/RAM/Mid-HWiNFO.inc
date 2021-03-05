[Variables]
@Include5=#@#Include\PanelStyleMid.inc
@Include6=#@#HWiNFO-Sensors.inc
RAMHWiNFODistance=0.16


;---- Standard Windows Measures ----

[Measure_MaxRAM]
Measure				=PhysicalMemory
Total				=1

[Measure_RAM0]
Measure				=PhysicalMemory

[Measure_RAM1]
Measure				=Calc
Formula				=Measure_MaxRAM-Measure_RAM0

[Measure_MaxSwap]
Measure				=SwapMemory
Total				=1

[Measure_Swap0]
Measure				=SwapMemory

[Measure_Swap1]
Measure				=Calc
Formula				=Measure_MaxSwap-Measure_Swap0

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

[Measure_SwapPercentage0]
Measure				=Calc
Formula				=100-100*(Measure_Swap0/Measure_MaxSwap)

[Measure_SwapPercentage1]
Measure				=Calc
Formula				=100*(Measure_Swap0/Measure_MaxSwap)


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

[Measure_DRAMTRCD]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#DRAM-TRCD_Id#
HWiNFOSensorInstance=#DRAM-TRCD_Instance#
HWiNFOEntryId		=#DRAM-TRCD_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=-1

[Measure_DRAMTRP]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#DRAM-TRP_Id#
HWiNFOSensorInstance=#DRAM-TRP_Instance#
HWiNFOEntryId		=#DRAM-TRP_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=-1

[Measure_DRAMTRAS]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#DRAM-TRAS_Id#
HWiNFOSensorInstance=#DRAM-TRAS_Instance#
HWiNFOEntryId		=#DRAM-TRAS_EntryId#
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

[Measure_DRAMTemp_available]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#DRAM-Temp_Id#
HWiNFOSensorInstance=#DRAM-Temp_Instance#
HWiNFOEntryId		=#DRAM-Temp_EntryId#
HWiNFOType			=Units
IfMatch				=C|F
IfNotMatchAction	=[!SetVariable RAMHWiNFODistance 0.20][!HideMeterGroup RAMTEMP]
UpdateDivider		=-1

[Measure_RAMName]
Measure				=Calc
Formula				=2*Measure_DRAMClock
UpdateDivider		=-1


;---- Standard Meter ----

[Info]
	Meter=String
	MeterStyle=PText | PInfo | PCenterMid
	Y=(#PHeight#*0.03)
	Text=#VarUsed#
	
[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#RAMColoredIcons#.png
	X=(#PHeight#*0.13+#RAMHideGraph#*#PHeight#*0.03)
	Y=(#PHeight#*0.2)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#RAMColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
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

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Swap#RAMColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*#RAMHWiNFODistance#)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Swap#RAMColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_Swap0
	MeasureName2=Measure_Swap1
	MeasureName3=Measure_SwapPercentage1
	MeasureName4=Measure_SwapPercentage0
	MeasureName5=Measure_DRAMTemp
	Text=%1B
	NumOfDecimals=1
	AutoScale=1

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#RAMColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*#RAMHWiNFODistance#)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#RAMColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DRAMClock
	Text=%1 MHz
	NumOfDecimals=0

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\DRAM#RAMColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*#RAMHWiNFODistance#)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\DRAM#RAMColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DRAMTCAS
	MeasureName2=Measure_DRAMTRCD
	MeasureName3=Measure_DRAMTRP
	Text=CL%1-%2-%3

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#RAMColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*#RAMHWiNFODistance#)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
	Group=RAMTEMP
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#RAMColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
	Group=RAMTEMP
[Info5Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DRAMTemp
	Text=%1[\x00B0]#TempUnit#
	Group=RAMTEMP
	
[Title]
	Meter=String
	MeasureName=Measure_RAMName
	MeterStyle=PText | PTitle
	Text=#RAMName#

;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#RAMHideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_RAMPercentage#RAMShowFreeSpace#
UpdateDivider=1
Hidden=#RAMHideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#RAMHideGraph#


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#RAMShowPercentage#+#RAMShowFreeSpace#+#RAMShowRAMonly#
	UpdateRate=-1
	IfCondition=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info Text #VarUsed#][!SetOption Info1Text Text "%1B"][!SetOption Info2Text Text "%1B"]
	IfCondition2=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info Text #VarFree#][!SetOption Info1Text Text "%2B"][!SetOption Info2Text Text "%2B"]
	IfCondition3=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info Text #VarUsed#][!SetOption Info1Text Text "%3%"][!SetOption Info2Text Text "%3%"]
	IfCondition4=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info Text #VarFree#][!SetOption Info1Text Text "%4%"][!SetOption Info2Text Text "%4%"]
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