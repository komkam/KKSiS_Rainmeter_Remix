[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc


---- Measures Volume ----

[VolumeWin]
Measure			=Plugin
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinPercent]
Measure			=Calc
Formula			=VolumeWin
UpdateDivider	=1
IfCondition		=(VolumeWinPercent = -1) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfFalseAction	=[!HideMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfCondition2	=(VolumeWinPercent > 0) && (#WRActive# = 1)
IfTrueAction2	=[!HideMeter "ButtonMute"][!ShowMeter "ButtonVol"]
DynamicVariables=1

[VolumeWinSmooth]
Measure=Calc
Formula=100-VolumeWin
MaxValue=100
MinValue=0
AverageSize=6
UpdateDivider=1

[FunctionSwitch]
Measure			=Calc
Formula			=#WRHideVolume#
IfCondition		=(#WRHideVolume# = 0) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "Volume"]
IfFalseAction	=[!HideMeter "Volume"]
DynamicVariables=1
Updatedivider	=-1


;---- Measures Audiolevel ----

[WinAudioLevel]
	Measure=Plugin
	Plugin=AudioLevel
	Port=Output
	FFTSize=1024
	FFTAttack=15
	FFTDecay=200
	Bands=20
	UpdateDivier=1
[Band0]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=0
	InvertMeasure=1
[Band1]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=1
	InvertMeasure=1
[Band2]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=2
	InvertMeasure=1
[Band3]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=3
	InvertMeasure=1
[Band4]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=4
	InvertMeasure=1
[Band5]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=5
	InvertMeasure=1
[Band6]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=6
	InvertMeasure=1
[Band7]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=7
	InvertMeasure=1
[Band8]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=8
	InvertMeasure=1
[Band9]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=9
	InvertMeasure=1
[Band10]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=10
	InvertMeasure=1
[Band11]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=11
	InvertMeasure=1
[Band12]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=12
	InvertMeasure=1
[Band13]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=13
	InvertMeasure=1
[Band14]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=14
	InvertMeasure=1
[Band15]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=15
	InvertMeasure=1
[Band16]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=16
	InvertMeasure=1
[Band17]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=17
	InvertMeasure=1
[Band18]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=18
	InvertMeasure=1
[Band19]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=19
	InvertMeasure=1


;---- Default Cover & Station ----

[SpeakerLogo]
	Meter=Image
	ImageName=#@#Images\General\Speaker.png
	X=(#PHeight#*0.15)
	Y=(#PHeight#*0.1)
	W=(#PHeight#*0.8)
	H=(#PHeight#*0.8)
	Hidden=#WRActive#
	Group=RadioOff
	DynamicVariables=1
	Updatedivider=-1

[Title]
	Meter=String
	MeterStyle=PText | PTitle
	Text=Webradio
	Group=RadioOff
	Hidden=#WRActive#
	DynamicVariables=1
	Updatedivider=-1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
MouseScrollDownAction=[!CommandMeasure "VolumeWin" "ChangeVolume -3"]
MouseScrollUpAction=[!CommandMeasure "VolumeWin" "ChangeVolume +3"]


;---- Active Cover & Station ----

[Cover]
	Meter=Image
	ImageName=#@#Images\Stations\#WRASImage#
	AntiAlias=1
	X=(#PHeight#*0.29)
	Y=(#PHeight#*0.07)
	W=(#PHeight#*0.70)
	H=(#PHeight#*0.70)
	Hidden=#WRInactive#
	Group=Radio
	LeftMouseUpAction=[#WRASTracklist#]
	DynamicVariables=1
	UpdateDivider=10

[Volume]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=Center
	MeasureName=VolumeWinPercent
	X=(#PHeight#*0.16)
	Y=(#PHeight#*0.08)
	Group=Radio
	Hidden=#WRInactive#
	Text=Vol#CRLF#%1
	UpdateDivider=3


;---- Audiolevelmeter ----

[StyleAudioBarBack]
	Meter=Shape
	Audiobarfill1=90 | #Panel-BarFillColor1# ; 1 | #Panel-BarFillColor1# ; 0.01
	Audiobarfill2=90 | #Panel-BarFillColor1# ; 1.0 |  #Panel-BarFillColor1# ; (#Panel-BarFillArc#+0.3) | #Panel-BarFillColor3# ; (#Panel-BarFillArc#-0.3) | #Panel-BarFillColor3# ; 0.01
	Audiobarfill3=90 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor2# ; #Panel-BarFillArc# | #Panel-BarFillColor3# ; 0.01
	DynamicVariables=1
	AntiAlias=1
	Hidden=#WRInactive#
	Group=Radio
	UpdateDivider=-1

[StyleAudioBar]
	Flip=1
	BarColor=#Panel-BarColor#
	SolidColor=0,0,0,0
	BarOrientation=Vertical
	X=0
	Y=0
	W=(#PHeight#*0.036)
	H=(#PHeight#*0.206)
	Group=Radio
	AntiAlias=1
	DynamicVariables=1
	Hidden=#WRInactive#
	UpdateDivider=1

[AudioBarBack0]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.05);(#PHeight#*0.8)
[MeterBand0]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band0
	TransformationMatrix=1;0;0;1;(#PHeight#*0.047);(#PHeight#*0.797)

[AudioBarBack1]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.10);(#PHeight#*0.8)
[MeterBand1]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band1
	TransformationMatrix=1;0;0;1;(#PHeight#*0.097);(#PHeight#*0.797)

[AudioBarBack2]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.15);(#PHeight#*0.8)
[MeterBand2]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band2
	TransformationMatrix=1;0;0;1;(#PHeight#*0.147);(#PHeight#*0.797)

[AudioBarBack3]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.20);(#PHeight#*0.8)
[MeterBand3]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band3
	TransformationMatrix=1;0;0;1;(#PHeight#*0.197);(#PHeight#*0.797)

[AudioBarBack4]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.25);(#PHeight#*0.8)
[MeterBand4]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band4
	TransformationMatrix=1;0;0;1;(#PHeight#*0.247);(#PHeight#*0.797)

[AudioBarBack5]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.30);(#PHeight#*0.8)
[MeterBand5]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band5
	TransformationMatrix=1;0;0;1;(#PHeight#*0.297);(#PHeight#*0.797)

[AudioBarBack6]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.35);(#PHeight#*0.8)
[MeterBand6]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band6
	TransformationMatrix=1;0;0;1;(#PHeight#*0.347);(#PHeight#*0.797)

[AudioBarBack7]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.40);(#PHeight#*0.8)
[MeterBand7]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band7
	TransformationMatrix=1;0;0;1;(#PHeight#*0.397);(#PHeight#*0.797)

[AudioBarBack8]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.45);(#PHeight#*0.8)
[MeterBand8]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band8
	TransformationMatrix=1;0;0;1;(#PHeight#*0.447);(#PHeight#*0.797)

[AudioBarBack9]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.50);(#PHeight#*0.8)
[MeterBand9]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band9
	TransformationMatrix=1;0;0;1;(#PHeight#*0.497);(#PHeight#*0.797)
	
[AudioBarBack10]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.55);(#PHeight#*0.8)
[MeterBand10]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band10
	TransformationMatrix=1;0;0;1;(#PHeight#*0.547);(#PHeight#*0.797)

[AudioBarBack11]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.60);(#PHeight#*0.8)
[MeterBand11]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band11
	TransformationMatrix=1;0;0;1;(#PHeight#*0.597);(#PHeight#*0.797)

[AudioBarBack12]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.65);(#PHeight#*0.8)
[MeterBand12]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band12
	TransformationMatrix=1;0;0;1;(#PHeight#*0.647);(#PHeight#*0.797)

[AudioBarBack13]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.70);(#PHeight#*0.8)
[MeterBand13]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band13
	TransformationMatrix=1;0;0;1;(#PHeight#*0.697);(#PHeight#*0.797)

[AudioBarBack14]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.75);(#PHeight#*0.8)
[MeterBand14]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band14
	TransformationMatrix=1;0;0;1;(#PHeight#*0.747);(#PHeight#*0.797)	

[AudioBarBack15]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.80);(#PHeight#*0.8)
[MeterBand15]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band15
	TransformationMatrix=1;0;0;1;(#PHeight#*0.797);(#PHeight#*0.797)	

[AudioBarBack16]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.85);(#PHeight#*0.8)
[MeterBand16]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band16
	TransformationMatrix=1;0;0;1;(#PHeight#*0.847);(#PHeight#*0.797)

[AudioBarBack17]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.90);(#PHeight#*0.8)
[MeterBand17]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band17
	TransformationMatrix=1;0;0;1;(#PHeight#*0.897);(#PHeight#*0.797)

[AudioBarBack18]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*0.95);(#PHeight#*0.8)
[MeterBand18]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band18
	TransformationMatrix=1;0;0;1;(#PHeight#*0.947);(#PHeight#*0.797)	
	
[AudioBarBack19]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#PHeight#*0.03),(#PHeight#*0.2) | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-BarColor# | Fill LinearGradient Audiobarfill#Panel-BarFillStyle#
	TransformationMatrix=1;0;0;1;(#PHeight#*1.00);(#PHeight#*0.8)
[MeterBand19]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band19
	TransformationMatrix=1;0;0;1;(#PHeight#*0.997);(#PHeight#*0.797)


;---- Buttons ----

[ButtonFrameColored]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.11),(#PHeight#*0.30),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	Shape2=Rectangle (#PHeight#*0.11),(#PHeight#*0.45),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	Shape3=Rectangle (#PHeight#*0.11),(#PHeight#*0.60),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	ButtonFrameColor01=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor02=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor03=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor11=90 | #Panel-BarFillColor1# ; 0.0 | #Panel-BarFillColor1# ; 1.0
	ButtonFrameColor12=90 | #Panel-BarFillColor3# ; 0.0 |  #Panel-BarFillColor1# ; 1.0
	ButtonFrameColor13=90 | #Panel-BarFillColor3# ; 0.0 | #Panel-BarFillColor2# ; 0.5 | #Panel-BarFillColor1# ; 1.0
	DynamicVariables=1
	AntiAlias=1
	Hidden=#WRInactive#
	Group=Radio
	UpdateDivider=10

[ButtonVol]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVol.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)	
	Y=(#PHeight#*0.32)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonVol ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonVol ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonMute]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVolMute.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)	
	Y=(#PHeight#*0.32)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonMute ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonMute ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonStop]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStop.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)	
	Y=(#PHeight#*0.47)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStop ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStop ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "1" "#@#Variables.inc"]["#@#Tools\omnimoapp.exe" Radio Kill][!HideMeterGroup Radio][!ShowMeterGroup RadioOff][!Redraw]
	UpdateDivider=1

[ButtonPlay]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPlay.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)		
	Y=(#PHeight#*0.62)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=1
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPlay ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPlay ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#WRASStream#"][!HideMeter ButtonPlay][!ShowMeter ButtonPause]
	UpdateDivider=1

[ButtonPause]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPause.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)		
	Y=(#PHeight#*0.62)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPause ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPause ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" Off][!HideMeter ButtonPause][!ShowMeter ButtonPlay]
	UpdateDivider=1


;---- Bar ----

[Bar1]
	Meter=Shape
	MeterStyle=BarStyle-VRx1
	UpdateDivider=10

[Bar1Measure]
	Meter=Bar
	MeterStyle=BarStyle-VRx1Measure
	MeasureName=VolumeWinSmooth
	UpdateDivider=1

[Bar1Stroke]
	Meter=Shape
	MeterStyle=BarStyle-VRx1Stroke
	UpdateDivider=10


;---- Skin Functions ----

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size


;---- Station list ----

[ShowStationMarker]
Meter=Image
ImageName=#@#Images\Buttons\Marker.png
ImageTint=#Panel-ButtonColor#
X=(#PHeight#*1.04)	
Y=(-#PHeight#*0.04+#PHeight#*0.12*#Stationmarker#)
H=(#PHeight#*0.06)	
W=(#PHeight#*0.06)
Hidden=#WRInactive#
DynamicVariables=1
Group=Radio

[Station1]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.03)	
Text=#StationTitle1#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "1"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle1#"][!WriteKeyValue Variables "WRASImage" "#StationImage1#"][!WriteKeyValue Variables "WRASStream" "#StationURL1#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL1#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL1#"][!Refresh]
MouseOverAction=[!SetOption Station1 FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption Station1 FontColor #Panel-FontColor#]

[Station2]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.15)	
Text=#StationTitle2#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "2"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle2#"][!WriteKeyValue Variables "WRASImage" "#StationImage2#"][!WriteKeyValue Variables "WRASStream" "#StationURL2#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL2#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL2#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station3]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.27)
Text=#StationTitle3#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "3"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle3#"][!WriteKeyValue Variables "WRASImage" "#StationImage3#"][!WriteKeyValue Variables "WRASStream" "#StationURL3#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL3#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL3#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station4]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.39)
Text=#StationTitle4#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "4"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle4#"][!WriteKeyValue Variables "WRASImage" "#StationImage4#"][!WriteKeyValue Variables "WRASStream" "#StationURL4#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL4#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL4#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station5]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.51)
Text=#StationTitle5#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "5"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle5#"][!WriteKeyValue Variables "WRASImage" "#StationImage5#"][!WriteKeyValue Variables "WRASStream" "#StationURL5#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL5#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL5#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station6]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.63)
Text=#StationTitle6#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "6"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle6#"][!WriteKeyValue Variables "WRASImage" "#StationImage6#"][!WriteKeyValue Variables "WRASStream" "#StationURL6#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL6#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL6#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station7]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.75)
Text=#StationTitle7#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "7"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle7#"][!WriteKeyValue Variables "WRASImage" "#StationImage7#"][!WriteKeyValue Variables "WRASStream" "#StationURL7#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL7#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL7#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station8]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.87)
Text=#StationTitle8#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "8"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle8#"][!WriteKeyValue Variables "WRASImage" "#StationImage8#"][!WriteKeyValue Variables "WRASStream" "#StationURL8#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL8#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL8#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]
