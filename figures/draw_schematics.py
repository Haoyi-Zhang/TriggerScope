"""Draw the manuscript schematics directly as font-embedded vector PDFs.

Run: python figures/draw_schematics.py --output figures
Requires Python 3.9+ and Matplotlib. No TeX engine or network is used.
The diagrams express the defined model; they are not measurement plots.
"""
import argparse
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Circle, FancyArrowPatch

plt.rcParams.update({'font.family':'STIXGeneral', 'mathtext.fontset':'stix',
                     'font.size':9, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'text.usetex':False, 'axes.unicode_minus':False})
CM = 1 / 2.54

class Drawing:
    def __init__(self, bounds):
        x0,y0,x1,y1 = bounds
        self.fig = plt.figure(figsize=((x1-x0)*CM,(y1-y0)*CM))
        self.ax = self.fig.add_axes([0,0,1,1], xlim=(x0,x1), ylim=(y0,y1))
        self.ax.set_aspect('equal'); self.ax.axis('off')
        self.nodes = {}
        self.labels = []

    def text(self,x,y,label,size=9,ha='center',va='center'):
        artist=self.ax.text(x,y,label,fontsize=size,ha=ha,va=va,
                            linespacing=1.15,clip_on=False,zorder=4)
        self.labels.append([artist,None])
        return artist

    def box(self,name,x,y,w,h,label,dashed=False,shape='rect',size=9):
        style = {'edgecolor':'black','facecolor':'white','linewidth':.55,
                 'linestyle':(0,(4,3)) if dashed else 'solid', 'zorder':2}
        if shape == 'diamond':
            obj = Polygon([(x-w/2,y),(x,y+h/2),(x+w/2,y),(x,y-h/2)],**style)
        elif shape == 'circle': obj = Circle((x,y),w/2,**style)
        else: obj = Rectangle((x-w/2,y-h/2),w,h,**style)
        self.ax.add_patch(obj); self.text(x,y,label,size)
        self.labels[-1][1]=(x-w/2,y-h/2,x+w/2,y+h/2)
        self.nodes[name] = (x,y,w,h,shape)

    def point(self,name,side):
        x,y,w,h,_ = self.nodes[name]
        return {'n':(x,y+h/2),'s':(x,y-h/2),'e':(x+w/2,y),
                'w':(x-w/2,y),'nw':(x-w/2,y+h/2),
                'ne':(x+w/2,y+h/2),'c':(x,y)}[side]

    def line(self,points,dashed=False):
        xs,ys=zip(*points)
        self.ax.plot(xs,ys,color='black',linewidth=.55,
                     linestyle=(0,(4,3)) if dashed else 'solid',zorder=1)

    def arrow(self,p,q,dashed=False,via=()):
        points=[p,*via,q]
        if via:self.line(points[:-1],dashed)
        self.ax.add_patch(FancyArrowPatch(points[-2],points[-1],
                         arrowstyle='-|>',mutation_scale=7.5,linewidth=.55,
                         color='black',shrinkA=0,shrinkB=0,
                         linestyle=(0,(4,3)) if dashed else 'solid',zorder=1))

    def edge(self,a,b,sa='s',sb='n',**kwargs):
        self.arrow(self.point(a,sa),self.point(b,sb),**kwargs)

    def frame(self,x,y,w,h):
        self.ax.add_patch(Rectangle((x,y),w,h,fill=False,edgecolor='black',
                                   linewidth=.55,linestyle=(0,(4,3)),zorder=0))

    def save(self,out,name):
        # Fixed physical canvas: do not enlarge or rasterize the scientific figure.
        self.fig.canvas.draw()
        renderer=self.fig.canvas.get_renderer()
        x0,x1=self.ax.get_xlim();y0,y1=self.ax.get_ylim()
        for artist,node in self.labels:
            b=artist.get_window_extent(renderer).transformed(self.ax.transData.inverted())
            if b.x0<x0-.02 or b.x1>x1+.02 or b.y0<y0-.02 or b.y1>y1+.02:
                raise ValueError(name+': clipped label '+repr(artist.get_text()))
            if node and (b.x0<node[0]-.02 or b.x1>node[2]+.02 or b.y0<node[1]-.02 or b.y1>node[3]+.02):
                raise ValueError(name+': label exceeds node '+repr(artist.get_text()))
        self.fig.savefig(out/(name+'.pdf'),format='pdf',
                         metadata={'Creator':'Python Matplotlib','Producer':None,
                                   'CreationDate':None,'ModDate':None})
        plt.close(self.fig)

def draw(out):
    d=Drawing((-1.9,-3.55,6.4,.8))
    d.box('m',0,0,3.2,1.1,'Declared source\nand exact counts',size=8.5)
    d.box('p',4.2,0,3.4,1.1,'Producer\nsearch and matching',size=8.5)
    d.box('c',4.2,-2.6,3.4,1.1,'Replay checker\nno optimizer',size=8.5)
    d.box('o',0,-2.6,3.4,1.3,'Exact spectrum\nand conditional\nwitnesses',size=8.5)
    d.edge('m','p','e','w')
    d.edge('p','c','e','e',via=[(6.15,0),(6.15,-2.6)])
    d.text(4.2,-1.3,'DAG, matching,\nHall obstruction',size=8.5)
    d.edge('c','o','w','e')
    d.arrow((1.6,-.55),(2.5,-2.05))
    label=d.text(.1,-1.3,'model and report',size=8.5)
    label.set_bbox({'facecolor':'white','edgecolor':'none','pad':.8})
    d.save(out,'pipeline')

    d=Drawing((-.65,-1.65,7.8,2.95))
    for i,y in enumerate([2.4,1.6,.8,-.25]):d.box('c'+str(i),0,y,.65,.65,'$c_'+str(i)+'$',shape='circle',size=8.5)
    for i,y in enumerate([1.6,-.25]):d.box('y'+str(i),3,y,2.2,.8,'$y_'+str(i)+'$\n$n_'+str(i)+'=2$',size=8.5)
    # Matching is undirected; the solid and other eligible edges remain distinct.
    for a,b,dashed in [('c0','y0',False),('c1','y0',False),('c2','y0',True),('c3','y1',True)]:
        d.line([d.point(a,'e'),d.point(b,'w')],dashed)
    d.frame(-.47,.325,.94,2.55)
    d.ax.patches[-1].set_linestyle((0,(1,2)))
    d.text(4.5,1.6,r'$T=\{c_0,c_1,c_2\}$'+'\n'+r'$|T|=3>2$'+'\n'+r'$p=2$',size=8.5,ha='left')
    d.text(4.5,-.15,'Three distinct tokens\nin cell $(y_1,c_3)$',size=8.5,ha='left')
    d.text(-.35,-1.13,'Solid: selected prefix matching.\nDashed: other positive-capacity edges.',size=8.5,ha='left')
    d.save(out,'hall')

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,default=Path(__file__).resolve().parent)
    output=parser.parse_args().output
    output.mkdir(parents=True,exist_ok=True)
    draw(output)
