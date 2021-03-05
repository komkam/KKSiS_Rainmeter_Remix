[variables]
@Include6=#@#HWiNFO-Sensors.inc
RAMHWiNFODistance=0.20

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

[Measure_RAMPercentage1]
Measure				=Calc
Formula				=100*(Measure_RAM0/Measure_MaxRAM)


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
IfCondition			=(Measure_DRAMTemp = 0)
IfTrueAction		=[!SetVariable RAMHWiNFODistance 0.25][!HideMeterGroup RAMTEMP]

[Measure_DRAMTemp2]
Measure				=Calc
Formula				=100-Measure_DRAMTemp

[Measure_RAMName]
Measure				=Calc
Formula				=2*Measure_DRAMClock
UpdateDivider		=-1


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=Measure_RAMPercentage#RAMShowFreeSpace#
ValueRemainder=100

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=Measure_SwapPercentage#RAMShowFreeSpace#
ValueRemainder=100

[LD-20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-199.3))
[LD-40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-172.3))
[LD-60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-145.3))
[LD-80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-118.3))
[LD+80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-62.7))
[LD+60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-35.7))
[LD+40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-8.7))
[LD+20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(18.3))

[GlossyEffect]
Meter=Shape
MeterStyle=GlossyEffectStyle


;---- Skin Functions ----

[KlickFunctions]
	Meter=Shape
	MeterStyle=KlickFunctionsBG
	LeftMouseUpAction=[!CommandMeasure SpecialFunction Run]
	MouseOverAction=[!ShowMeterGroup ProcList]
	MouseLeaveAction=[!HideMeterGroup ProcList]

[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
Parameter=perfmon/res


;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_MaxRAM
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=%1B
	AutoScale=1
	NumOfDecimals=0
	Hidden=#RAMHideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.456)
	Text=0
	Hidden=#RAMHideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_MaxSwap
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=%1B
	AutoScale=1
	NumOfDecimals=0
	Hidden=#RAMHideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.456)
	Text=0
	Hidden=#RAMHideRLLabel#


;---- Graph ----

[GraphLabel1]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.45)
	Y=(#CRadius#*1.4)
	Text=RAM Usage
	Hidden=#RAMHideGraph#

[GraphLabel2]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.55)
	Y=(#CRadius#*1.4)
	Text=Swap Usage
	Hidden=#RAMHideGraph#

[MeterRAMGraph]
	Meter=Line
	MeasureName=Measure_RAM#RAMShowFreeSpace#
	MeasureName2=Measure_Swap#RAMShowFreeSpace#
	LineCount=2
	MeterStyle=HWiNFOGraphStyle
	Hidden=#RAMHideGraph#


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#RAMColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*0.45)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#RAMColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=CText | CInfo
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
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(#RAMHWiNFODistance#+#RAMHideGraph#*0.05))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Swap#RAMColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=CText | CInfo
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
	ImageName=#@#Images\Icons\DRAM#RAMColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(#RAMHWiNFODistance#+#RAMHideGraph#*0.05))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\DRAM#RAMColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_DRAMTCAS
	MeasureName2=Measure_DRAMTRCD
	MeasureName3=Measure_DRAMTRP
	MeasureName4=Measure_DRAMTRAS
	Text=CL%1-%2-%3-%4

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#RAMColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(#RAMHWiNFODistance#+#RAMHideGraph#*0.05))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#RAMColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_DRAMClock
	Text=%1 MHz
	NumOfDecimals=0

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#RAMColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(#RAMHWiNFODistance#+#RAMHideGraph#*0.05))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
	Group=RAMTEMP
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#RAMColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
	Group=RAMTEMP
[Info5Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_DRAMTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=0
	Group=RAMTEMP
	
[Title]
	Meter=String
	MeasureName=Measure_RAMName
	MeterStyle=CText | CTitle
	Text=#RAMName#
	Hidden=0

;---- Options ----

[Selection]
	Measure=Calc
	Formula=#RAMShowPercentage#+#RAMShowFreeSpace#+#RAMShowRAMonly#+#RAMShowTemp#
	UpdateRate=-1
	IfCondition=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info Text #VarUsed#][!SetOption Info1Text Text "%1B"][!SetOption Info2Text Text "%1B"]
	IfCondition2=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info Text #VarFree#][!SetOption Info1Text Text "%2B"][!SetOption Info2Text Text "%2B"]
	IfCondition3=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info Text #VarUsed#][!SetOption Info1Text Text "%3%"][!SetOption Info2Text Text "%3%"]
	IfCondition4=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info Text #VarFree#][!SetOption Info1Text Text "%4%"][!SetOption Info2Text Text "%4%"]
	IfCondition5=(#RAMShowRAMonly# = 1)
	IfTrueAction5=[!SetOption "Measure-Roundline-Right" "MeasureName" "Measure_RAMPercentage#RAMShowFreeSpace#"][!SetOption "SensorRightMax" "MeasureName" "Measure_MaxRAM"]
	IfCondition6=(#RAMShowTemp# = 1)
	IfTrueAction6=[!SetOption Info2Text Text "%5[\x00B0]#TempUnit#"][!SetOption Info2IconA ImageName "#@#Images\Icons\Temp#RAMColoredIcons#.png"][!SetOption Info2IconB ImageName "#@#Images\Icons\Temp#RAMColoredIcons#.png"][!SetOption MeterRAMGraph MeasureName2 Measure_DRAMTemp][!SetOption GraphLabel2 Text Temperature][!SetOption SensorRightMax Text "95[\x00B0]#TempUnit#"][!SetOption "Measure-Roundline-Right" MeasureName Measure_DRAMTemp2]
	DynamicVariables=1


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size


