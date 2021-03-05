[Variables]
@Include5=#@#Include\PanelStyleMid.inc


;---- Measures ----

[RecycleBinFiles]
Measure				=RecycleManager
RecycleType			=COUNT
Drives				=ALL
UpdateDivider		=1

[RecycleBinSize]
Measure				=RecycleManager
RecycleType			=SIZE
UpdateDivider		=1
IfCondition			=(RecycleBinSize = 0)
IfTrueAction		=[!HideMeterGroup BinFull][!ShowMeter BinImageEmpty]
IfFalseAction		=[!ShowMeterGroup BinFull][!HideMeter BinImageEmpty]

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

[BinImageFull]
	Meter=Image
	ImageName=#@#Images\General\Bin#TRBinType#b.png
	ImageTint=
	X=(#PHeight#*0.03)
	Y=(#PHeight#*0.25)
	W=(#PHeight#*0.5)
	H=(#PHeight#*0.5)
	DynamicVariables=1
	Group=BinFull

[BinFileText]
	Meter=String
	MeterStyle=PText | PSize5
	StringAlign=Left
	Text=#VarFiles#
	X=(#PHeight#*0.51)
	Y=(#PHeight#*0.15)
	UpdateDivider=-1
	Group=BinFull

[BinFiles]
	Meter=String
	MeterStyle=PText | PSize2
	MeasureName=RecycleBinFiles
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.1)r
	Group=BinFull

[BinSizeText]
	Meter=String
	MeterStyle=PText | PSize5
	StringAlign=Left
	Text=#VarTotal#
	X=0r
	Y=(#PHeight#*0.3)r
	Group=BinFull

[BinSize]
	Meter=String
	MeterStyle=PText | PSize2
	MeasureName=RecycleBinSize
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.1)r
	AutoScale=1
	NumOfDecimals=1
	Group=BinFull

[Title]
	Meter=String
	MeterStyle=PText | PTitle
	Text=#VarTrash#


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure RecycleBinSize OpenBin]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size
