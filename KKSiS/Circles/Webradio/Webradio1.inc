;---- Measures Volume ----

[VolumeWin]
Measure			=Plugin
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinInverted]
Measure			=Plugin
InvertMeasure	=1
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinPercent]
Measure			=Calc
Formula			=VolumeWin
UpdateDivider	=3
IfCondition		=(VolumeWinPercent = -1) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfFalseAction	=[!HideMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfCondition2	=(VolumeWinPercent > 0) && (#WRActive# = 1)
IfTrueAction2	=[!HideMeter "ButtonMute"][!ShowMeter "ButtonVol"]
DynamicVariables=1

[VolumeWinSmooth]
Measure			=Calc
Formula			=VolumeWinInverted
AverageSize		=6
UpdateDivider	=1


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


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=VolumeWinSmooth
ValueRemainder=100
Updatedivider=1

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=VolumeWinSmooth
ValueRemainder=100
Updatedivider=1

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
UpdateDivider=100
[LD+80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-62.7))
UpdateDivider=100
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
LeftMouseUpAction=[!ShowMeterGroup Stations]
MouseScrollDownAction=[!CommandMeasure "VolumeWin" "ChangeVolume -3"]
MouseScrollUpAction=[!CommandMeasure "VolumeWin" "ChangeVolume +3"]
Updatedivider=-1


;---- Default Cover & Station ----

[SpeakerLogo]
	Meter=Image
	ImageName=#@#Images\General\Speaker.png
	X=(#CRadius#*0.5)
	Y=(#CRadius#*0.5)
	W=(#CRadius#)
	H=(#CRadius#)
	Hidden=#WRActive#
	Group=RadioOff
	DynamicVariables=1
	Updatedivider=-1

[Volume]
	Meter=String
	MeterStyle=CText | CSize6 | CCenter
	MeasureName=VolumeWinPercent
	Y=(#CRadius#*0.16)
	Group=RadioOff
	Hidden=#WRHideVolume#
	Text=Vol %1
	UpdateDivider=3
	DynamicVariables=1

[Title]
	Meter=String
	MeterStyle=CText | CTitle
	Text=Webradio
	Group=RadioOff
	Hidden=#WRActive#
	DynamicVariables=1
	Updatedivider=-1


;---- Active Cover & Station ----

[Cover]
	Meter=Image
	ImageName=#@#Images\Stations\#WRASImage#
	AntiAlias=1
	X=(#CRadius#*0.61)
	Y=(#CRadius#*0.3)
	W=(#CRadius#*0.78)
	H=(#CRadius#*0.78)
	Hidden=#WRInactive#
	Group=Radio
	LeftMouseUpAction=[#WRASTracklist#]
	DynamicVariables=1
	UpdateDivider=10
	Container=CoverContainer

[CoverContainer]
	Meter=Shape
	Shape=Rectangle (#CRadius#*0.3),(#CRadius#*0.3),(#CRadius#*1.4),(#CRadius#*1.4),(#CRadius#*0.7) | StrokeWidth 0 | Fill Color 0,0,0
	DynamicVariables=1
	
[SationText]
	Meter=String
	MeterStyle=CText | CTitle
	Hidden=#WRInactive#
	Group=Radio
	Text=#WRASTitle#
	UpdateDivider=10


;---- Audiolevelmeter ----

[StyleAudioBarBack]
	Audiobarfill1=90 | #Circle-RoundlineFillColor1# ; 1 | #Circle-RoundlineFillColor1# ; 0.01
	Audiobarfill2=90 | #Circle-RoundlineFillColor1# ; 1.0 |  #Circle-RoundlineFillColor1# ; (#Circle-RoundlineFillArc#+0.3) | #Circle-RoundlineFillColor3# ; (#Circle-RoundlineFillArc#-0.3) | #Circle-RoundlineFillColor3# ; 0.01
	Audiobarfill3=90 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor2# ; #Circle-RoundlineFillArc# | #Circle-RoundlineFillColor3# ; 0.01
	DynamicVariables=1
	AntiAlias=1
	Hidden=#WRInactive#
	Group=Radio
	UpdateDivider=-1
	Container=CoverContainer
	
[StyleAudioBar]
	Flip=1
	BarColor=#Circle-BarColor#
	SolidColor=0,0,0,0
	BarOrientation=Vertical
	X=0
	Y=0
	W=(#CRadius#*0.06)
	H=(#CRadius#*0.30)
	Group=Radio
	AntiAlias=1
	DynamicVariables=1
	Hidden=#WRInactive#
	UpdateDivider=1
	Container=CoverContainer

[AudioBarBack0]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.295);(#CRadius#*1.1)
[MeterBand0]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band0
	TransformationMatrix=1;0;0;1;(#CRadius#*0.290);(#CRadius#*1.095)

[AudioBarBack1]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.367);(#CRadius#*1.1)
[MeterBand1]
	Meter=Bar
	MeasureName=Band1
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.362);(#CRadius#*1.095)

[AudioBarBack2]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.438);(#CRadius#*1.1)
[MeterBand2]
	Meter=Bar
	MeasureName=Band2
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.433);(#CRadius#*1.095)

[AudioBarBack3]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.510);(#CRadius#*1.1)
[MeterBand3]
	Meter=Bar
	MeasureName=Band3
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.505);(#CRadius#*1.095)

[AudioBarBack4]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.581);(#CRadius#*1.1)
[MeterBand4]
	Meter=Bar
	MeasureName=Band4
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.576);(#CRadius#*1.095)

[AudioBarBack5]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.653);(#CRadius#*1.1)
[MeterBand5]
	Meter=Bar
	MeasureName=Band5
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.648);(#CRadius#*1.095)

[AudioBarBack6]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.724);(#CRadius#*1.1)
[MeterBand6]
	Meter=Bar
	MeasureName=Band6
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.719);(#CRadius#*1.095)

[AudioBarBack7]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.796);(#CRadius#*1.1)
[MeterBand7]
	Meter=Bar
	MeasureName=Band7
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.791);(#CRadius#*1.095)

[AudioBarBack8]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.867);(#CRadius#*1.1)
[MeterBand8]
	Meter=Bar
	MeasureName=Band8
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.862);(#CRadius#*1.095)

[AudioBarBack9]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*0.939);(#CRadius#*1.1)
[MeterBand9]
	Meter=Bar
	MeasureName=Band9
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*0.934);(#CRadius#*1.095)

[AudioBarBack10]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.010);(#CRadius#*1.1)
[MeterBand10]
	Meter=Bar
	MeasureName=Band10
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.005);(#CRadius#*1.095)

[AudioBarBack11]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.082);(#CRadius#*1.1)
[MeterBand11]
	Meter=Bar
	MeasureName=Band11
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.077);(#CRadius#*1.095)

[AudioBarBack12]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.153);(#CRadius#*1.1)
[MeterBand12]
	Meter=Bar
	MeasureName=Band12
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.148);(#CRadius#*1.095)

[AudioBarBack13]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.225);(#CRadius#*1.1)
[MeterBand13]
	Meter=Bar
	MeasureName=Band13
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.220);(#CRadius#*1.095)

[AudioBarBack14]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.296);(#CRadius#*1.1)
[MeterBand14]
	Meter=Bar
	MeasureName=Band14
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.291);(#CRadius#*1.095)

[AudioBarBack15]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.368);(#CRadius#*1.1)
[MeterBand15]
	Meter=Bar
	MeasureName=Band15
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.363);(#CRadius#*1.095)

[AudioBarBack16]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.439);(#CRadius#*1.1)
[MeterBand16]
	Meter=Bar
	MeasureName=Band16
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.434);(#CRadius#*1.095)

[AudioBarBack17]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.511);(#CRadius#*1.1)
[MeterBand17]
	Meter=Bar
	MeasureName=Band17
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.506);(#CRadius#*1.095)

[AudioBarBack18]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.582);(#CRadius#*1.1)
[MeterBand18]
	Meter=Bar
	MeasureName=Band18
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.577);(#CRadius#*1.095)
	
[AudioBarBack19]
	Meter=Shape
	MeterStyle=StyleAudioBarBack
	Shape=Rectangle 0,0,(#CRadius#*0.05),(#CRadius#*0.29) | StrokeWidth (#CRadius#*0.008) | Stroke Color #Circle-BarColor# | Fill LinearGradient Audiobarfill#Circle-RoundlineFillStyle#
	TransformationMatrix=1;0;0;1;(#CRadius#*1.654);(#CRadius#*1.1)
[MeterBand19]
	Meter=Bar
	MeasureName=Band19
	MeterStyle=StyleAudiobar
	TransformationMatrix=1;0;0;1;(#CRadius#*1.649);(#CRadius#*1.095)


;---- Buttons ----

[ButtonFrame]
	Meter=Shape
	Shape=Rectangle (#CRadius#*0.62),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.015) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape2=Rectangle (#CRadius#*0.82),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.015) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape3=Rectangle (#CRadius#*1.02),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.015) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape4=Rectangle (#CRadius#*1.22),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.015) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle#| Fill Color 0,0,0,0
	ButtonFrameColor01=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor02=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor03=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor11=90 | #Circle-RoundlineFillColor1# ; 0.0 | #Circle-RoundlineFillColor1# ; 1.0
	ButtonFrameColor12=90 | #Circle-RoundlineFillColor3# ; 0.0 |  #Circle-RoundlineFillColor1# ; 1.0
	ButtonFrameColor13=90 | #Circle-RoundlineFillColor3# ; 0.0 | #Circle-RoundlineFillColor2# ; 0.5 | #Circle-RoundlineFillColor1# ; 1.0
	DynamicVariables=1
	AntiAlias=1
	Hidden=#WRInactive#
	Group=Radio
	UpdateDivider=-1

[ButtonVol]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVol.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.652)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonVol ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonVol ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonMute]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVolMute.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.652)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonMute ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonMute ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonStop]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStop.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.852)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStop ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStop ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!SetVariable "WRActive" "0"][!WriteKeyValue Variables "WRActive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "1" "#@#Variables.inc"]["#@#Tools\omnimoapp.exe" Radio Kill][!HideMeterGroup Radio][!ShowMeterGroup RadioOff][!Redraw]
	UpdateDivider=1

[ButtonPlay]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPlay.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.052)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=1
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPlay ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPlay ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#WRASStream#"][!HideMeter ButtonPlay][!ShowMeter ButtonPause]
	UpdateDivider=1

[ButtonPause]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPause.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.052)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPause ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPause ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" Off][!HideMeter ButtonPause][!ShowMeter ButtonPlay]
	UpdateDivider=1

[ButtonStations]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStations.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.252)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStations ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStations ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!ShowMeterGroup Stations]
	UpdateDivider=1


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size
UpdateDivider=-1


;---- Station list ----

[Stationlistbackground]
Meter=Shape
Shape=Rectangle 0,0,(#CRadius#*2),(#CRadius#*2),(#CRadius#*0.1) | Fill Color 0,0,0,200 | StrokeWidth (#CRadius#*0.004) | Stroke Color 255,255,255
Group=Stations
DynamicVariables=1
AntiAlias=1
Hidden=1
MouseLeaveAction=[!HideMeterGroup Stations]
UpdateDivider=-1

[Station1]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.05)	
Text=#StationTitle1#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle1#"][!WriteKeyValue Variables "WRASImage" "#StationImage1#"][!WriteKeyValue Variables "WRASStream" "#StationURL1#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL1#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL1#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption Station1 FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption Station1 FontColor 210,210,210,255]

[Station2]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.28)	
Text=#StationTitle2#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle2#"][!WriteKeyValue Variables "WRASImage" "#StationImage2#"][!WriteKeyValue Variables "WRASStream" "#StationURL2#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL2#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL2#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station3]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.51)	
Text=#StationTitle3#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle3#"][!WriteKeyValue Variables "WRASImage" "#StationImage3#"][!WriteKeyValue Variables "WRASStream" "#StationURL3#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL3#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL3#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station4]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.74)	
Text=#StationTitle4#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle4#"][!WriteKeyValue Variables "WRASImage" "#StationImage4#"][!WriteKeyValue Variables "WRASStream" "#StationURL4#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL4#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL4#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station5]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.97)	
Text=#StationTitle5#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle5#"][!WriteKeyValue Variables "WRASImage" "#StationImage5#"][!WriteKeyValue Variables "WRASStream" "#StationURL5#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL5#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL5#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station6]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.20)	
Text=#StationTitle6#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle6#"][!WriteKeyValue Variables "WRASImage" "#StationImage6#"][!WriteKeyValue Variables "WRASStream" "#StationURL6#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL6#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL6#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station7]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.43)	
Text=#StationTitle7#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle7#"][!WriteKeyValue Variables "WRASImage" "#StationImage7#"][!WriteKeyValue Variables "WRASStream" "#StationURL7#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL7#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL7#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station8]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.66)	
Text=#StationTitle8#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle8#"][!WriteKeyValue Variables "WRASImage" "#StationImage8#"][!WriteKeyValue Variables "WRASStream" "#StationURL8#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL8#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL8#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

