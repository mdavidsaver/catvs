#define NOMINMAX 1 // avoid min() and max() macros from windows.h

#include <iostream>
#include <vector>
#include <iterator>
#include <memory>
#include <limits>
#include <string>

#include "fdManager.h"
#include "casdef.h"
#include "gddApps.h"

namespace {

template<typename T> struct type2ait {};
template<> struct type2ait<epicsInt32> { enum etype {value=aitEnumInt32}; };
template<> struct type2ait<epicsInt16> { enum etype {value=aitEnumInt16}; };

volatile unsigned done;

template<typename T>
struct mailbox : public casPV
{
    const std::string name;
    std::vector<T> value; // don't resize
    epicsUInt16 sevr, stat;
    epicsTime stamp;

    struct gdd_ptr {
        gdd * const G;
        gdd_ptr(gdd *G) :G(G) {}
        ~gdd_ptr() {
            G->unreference();
        }
    };

    static gdd* allocGDD(size_t size)
    {
        aitEnum prim = (aitEnum)type2ait<T>::value;
        if(size==1)
            return new gddScalar(gddAppType_value, prim);
        else
            return new gddArray(gddAppType_value, prim, 1, size); // I refuse to use the vararg ctor
    }

    explicit mailbox(const char *name, size_t size)
        :name(name)
        ,value(size, T())
        ,sevr(NO_ALARM)
        ,stat(NO_ALARM)
        ,stamp()
    {
        stamp = epicsTime::getCurrent();
    }

    virtual ~mailbox() {}

    virtual void destroy() {}

    virtual aitEnum bestExternalType () const
    {
        return (aitEnum)type2ait<T>::value;
    }

    virtual unsigned maxDimension () const { return 1u; }
    virtual aitIndex maxBound ( unsigned dimension ) const { return value.size(); }

    virtual const char * getName() const { return name.c_str(); }

    virtual void show ( unsigned level ) const
    {
        std::cout<<name<<" : [";
        std::copy(value.begin(),
                  value.end(),
                  std::ostream_iterator<T>(std::cout, ", "));
        std::cout<<"]\n";
    }

    gddStatus readValue(gdd& V)
    {
        switch(V.applicationType()) {
        case gddAppType_value:
            V.setSevr(sevr);
            V.setStat(stat);
        {
            epicsTimeStamp ts(stamp);
            V.setTimeStamp(&ts);
        }
            if(value.size()>1 && V.dimension()==1) {
                gddDestructor* dtor=NULL;
                T* buf;
                try {
                    dtor = new gddDestructor; // default uses delete[]
                    buf = new T[value.size()];
                }catch(std::bad_alloc&){
                    // f'ing ~gddDestructor is hidden
                    if(dtor) dtor->destroy(NULL);
                    return S_cas_noMemory;
                }
                std::copy(value.begin(),
                          value.end(),
                          buf);
                V.putRef(buf, dtor);
                V.setBound(0, 0, value.size()); // maybe unnecessary?
                return 0;
            } else {
                // assume V.bounds are <= our storage
                return V.genCopy((aitEnum)type2ait<T>::value, &value[0]);
            }

        case gddAppType_graphicHigh:
            return V.put(std::numeric_limits<T>::max());

        case gddAppType_graphicLow:
            return V.put(std::numeric_limits<T>::min());

        default:
            std::cout<<"read() w/ gdd nested unknown "<<V.applicationType()<<"\n";
            return 0;
        }
    }

    virtual caStatus read (const casCtx &ctx, gdd &V)
    {
        gddStatus status=0;
        if(V.isContainer()) {
            // PCAS requesting value and/or meta-data
            gddContainer& C=(gddContainer&)V;
            gddCursor cur = C.getCursor();

            for(gdd *I = cur.first(); I && !status; I=cur.next()) {
                if(I->isContainer()) {
                    status = 1;
                    std::cout<<"read() ignore gdd nested container\n";
                    break;
                }
                status = readValue(*I);
            }
        } else {
            status = readValue(V);
        }
        return status ? S_cas_noConvert : 0;
    }

    virtual caStatus write(const casCtx &ctx, const gdd &V)
    {
        // only write of plain value is supported
        if(V.isContainer() || V.applicationType()!=gddAppType_value) {
            return S_cas_noConvert;
        }

        // update value
        V.outData(&value[0], sizeof(T)*value.size(), (aitEnum)type2ait<T>::value, aitLocalDataFormat);
        // refresh timestamp
        stamp = epicsTime::getCurrent();

        gdd_ptr ptr(allocGDD(value.size()));
        readValue(*ptr.G);

        caServer * cas = getCAS();
        if ( cas != NULL ) {
            casEventMask select ( cas->valueEventMask() | cas->logEventMask() );
            this->postEvent ( select, *ptr.G );
        }
        return 0;
    }
};

struct imdone : public mailbox<epicsInt32>
{
    imdone(const char *name)
        :mailbox<epicsInt32>(name, 1)
    {}
    virtual ~imdone() {}
    virtual caStatus write(const casCtx &ctx, const gdd &V)
    {
        caStatus ret = mailbox<epicsInt32>::write(ctx, V);
        if(!ret) {
            done = value[0];
        }
        return ret;
    }
};

struct testServer : public caServer
{
    mailbox<epicsInt32> ival;
    mailbox<epicsInt16> aval;
    imdone done;

    testServer()
        :caServer()
        ,ival("ival", 1)
        ,aval("aval", 5)
        ,done("done")
    {
        ival.value[0] = 42;
    }

    virtual pvExistReturn pvExistTest(const casCtx &ctx, const char *name)
    {
        if(   strcmp(name, "ival")==0
           || strcmp(name, "aval")==0
           || strcmp(name, "done")==0) {
            return pverExistsHere;
        }
        return pverDoesNotExistHere;
    }

    virtual pvAttachReturn pvAttach(const casCtx &ctx, const char *name)
    {
        if(strcmp(name, "ival")==0) {
            return ival;
        } else if(strcmp(name, "aval")==0) {
            return aval;
        } else if(strcmp(name, "done")==0) {
            return done;
        }
        return S_casApp_pvNotFound;
    }
};

} // namespace

int main(int argc, char *argv[])
{
    try {
        std::auto_ptr<testServer> server(new testServer);

        while(!done)
            fileDescriptorManager.process(1000);

        return 0;
    }catch(std::exception& e){
        std::cerr<<"Error: "<<e.what()<<"\n";
        return 1;
    }catch(int i){
        char buf[64];
        errSymLookup(i, buf, sizeof(buf));
        std::cerr<<"Error Code: "<<buf<<"\n";
        return 1;
    }catch(...){
        std::cerr<<"Unknown Error\n";
        return 2;
    }
}
