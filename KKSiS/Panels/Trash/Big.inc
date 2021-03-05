[Rainmeter]
Update=100

[Variables]
@Include5=#@#Include\PanelStyleBig.inc


;---- Measures ----

[RecycleBinFiles]
Measure				=RecycleManager
RecycleType			=COUNT
Drives				=ALL
UpdateDivider		=10

[RecycleBinSize]
Measure				=RecycleManager
RecycleType			=SIZE
UpdateDivider		=1
IfCondition			=(RecycleBinSize = 0)
IfTrueAction		=[!HideMeterGroup BinFull][!ShowMeter BinImageEmpty]
IfFalseAction		=[!ShowMeterGroup BinFull][!HideMeter BinImageEmpty]
IfCondition2		=(RecycleBinSize > #TRMaxSize#*1024*1024)
IfTrueAction2		=[!SetOption SmoothRecycleBin Formula "0.1"]
IfFalseAction2		=[!SetOption SmoothRecycleBin Formula "100-100*(RecycleBinSize+0.1)/(#TRMaxSize#*1024*1024)"]

[BinColor]
Measure				=Calc
Formula				=#Panel-TRColored#
IfCondition			=BinColor = 1
IfTrueAction		=[!SetOption BinImageEmpty ImageTint #Panel-BarFillColor3#][!SetOption BinImageFull ImageTint #Panel-BarFillColor1#]
IfFalseAction		=[!SetOption BinImageEmpty ImageTint ""][!SetOption BinImageFull ImageTint ""]
IfCondition2		=(#Panel-TRColored# = 0) && (#TRBinType# = 5)
IfTrueAction2		=[!SetOption BinImageEmpty ImageTint #Panel-ButtonColor#][!SetOption BinImageFull ImageTint #Panel-ButtonColor#]
DynamicVariables	=1
UpdateDivider		=-1

[SmoothRecycleBin]
Measure				=Calc
Formula				=100-100*(RecycleBinSize+0.1)/(#TRMaxSize#*1024*1024)
MaxValue			=100
MinValue			=0
AverageSize			=30
DynamicVariables	=1


;---- Meters ----

[BinImageEmpty]
	Meter=Image
	ImageName=#@#Images\General\Bin#TRBinType#a.png
	ImageTint=
	X=(#PHeight#*0.2)
	Y=(#PHeight#*0.18)
	W=(#PHeight#*0.7)
	H=(#PHeight#*0.7)
	DynamicVariables=1
	UpdateDivider=-1

[BinImageFull]
	Meter=Image
	ImageName=#@#Images\General\Bin#TRBinType#b.png
	ImageTint=
	X=(#PHeight#*0.2)
	Y=(#PHeight#*0.18)
	W=(#PHeight#*0.7)
	H=(#PHeight#*0.7)
	DynamicVariables=1
	Group=BinFull
	UpdateDivider=-1

[BinFileText]
	Meter=String
	MeterStyle=PText | PSize5
	StringAlign=Left
	Text=#VarFiles#
	X=(#PHeight#*1.1)
	Y=(#PHeight#*0.15)
	UpdateDivider=-1

[BinFiles]
	Meter=String
	MeterStyle=PText | PSize2
	MeasureName=RecycleBinFiles
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.1)r
	UpdateDivider=10

[BinSizeText]
	Meter=String
	MeterStyle=PText | PSize5
	StringAlign=Left
	Text=#VarTotal#
	X=0r
	Y=(#PHeight#*0.3)r
	UpdateDivider=-1

[BinSize]
	Meter=String
	MeterStyle=PText | PSize2
	MeasureName=RecycleBinSize
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.1)r
	AutoScale=1
	NumOfDecimals=1
	UpdateDivider=10

[Title]
	Meter=String
	MeterStyle=PText | PTitle
	Text=#VarTrash#
	UpdateDivider=-1


;---- Bar ----

[Bar1]
	Meter=Shape
	MeterStyle=BarStyle-VRx1
	UpdateDivider=10

[Bar1Measure]
	Meter=Bar
	MeterStyle=BarStyle-VRx1Measure
	MeasureName=SmoothRecycleBin
	UpdateDivider=10

[Bar1Stroke]
	Meter=Shape
	MeterStyle=BarStyle-VRx1Stroke
	UpdateDivider=10


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure RecycleBinSize OpenBin]
UpdateDivider=10

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size
UpdateDivider=10