use e2d2::headers::*;
use e2d2::operators::*;
use e2d2::utils::{Flow,Ipv4Prefix};
//use fnv::FnvHasher;
//use std::collections::HashSet;
use std::hash::BuildHasherDefault;
use std::time::{Duration, SystemTime};
use std::collections::HashMap;

//type FnvHash = BuildHasherDefault<FnvHasher>;

#[derive(Debug)]
pub struct Hashinfo {
    pub count: u32,
    pub epoch: SystemTime,
    pub totallength: u32,
    pub meanlength: u32,
    pub tos: u8,
    pub ttl: u8,
    pub tcpflags: Option<u8>,
    pub ipflags: u8,
}

impl Hashinfo {
    pub fn get_rate(&self) -> f64 {
        let cur_time = SystemTime::now();
        let difference = match cur_time.duration_since(self.epoch) {
            Ok(duration) => duration,
            Err(_) => Duration::from_millis(0),
        };
        let duration_secs = difference.as_secs() as f64;
        let duration_millis = difference.subsec_millis() as f64;
        let c = self.count as f64;
        c/(duration_secs * 1000.0 + duration_millis)
    }

    pub fn increment_count(&mut self) {
        self.count += 1;
    }

    pub fn get_count(&self) -> &u32 {
        &self.count
    }

    pub fn increment_length(&mut self, len: u16) {
        self.totallength += len as u32;
    }

    pub fn update_meanlength(&mut self) {
        self.meanlength = self.totallength / self.count;
    }

    pub fn increment_details(&mut self, len: u16) {
        self.increment_count();
        self.increment_length(len);
        self.update_meanlength();
    }

    pub fn set_tcpflags(&mut self, tcpflags: u8) {
        self.tcpflags = Some(tcpflags);
    }
}

#[derive(Clone)]
pub struct Acl {
    pub src_ip: Option<Ipv4Prefix>,
    pub dst_ip: Option<Ipv4Prefix>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub established: Option<bool>,
    pub threshold: Option<f64>,
    // Related not done
    pub drop: bool,
}

impl Acl {
    pub fn matches(&self, flow: &Flow, connections: &HashMap<Flow, Hashinfo>) -> bool {
        if (self.src_ip.is_none() || self.src_ip.unwrap().in_range(flow.src_ip))
            && (self.dst_ip.is_none() || self.dst_ip.unwrap().in_range(flow.dst_ip))
            && (self.src_port.is_none() || flow.src_port == self.src_port.unwrap())
            && (self.dst_port.is_none() || flow.dst_port == self.dst_port.unwrap())
            //&& (connections.get(&flow).get_count() > 1 && self.threshold <= connections.get(&flow).get_rate())
        {
            //println!("Flow: {:?}", &flow);
            //println!("ACL matches");
            println!("Connections: {:#?}", connections);
            if let Some(h) = connections.get(&flow) {
                //println!("Count: {}",h.get_count());
                //println!("Hashinfo: {:?}", &h);
                if let Some(thres) = self.threshold {
                    //println!("Threshold: {}",thres);
                    //println!("Rate: {}",h.get_rate());
                    if h.get_count() >= &1 && thres >= h.get_rate() {
                        if let Some(established) = self.established {
                            let rev_flow = flow.reverse_flow();
                            (connections.contains_key(&flow) || connections.contains_key(&rev_flow)) == established
                        } else {
                            true
                        }
                    } else {
                        //println!("False1");
                        false
                    }
                } else {
                    //println!("False2");
                    false
                }
            } else {
                //println!("False3");
                true
            }
        } else {
            //println!("False4");
            false
        }
    }
}

pub fn acl_match<T: 'static + Batch<Header = NullHeader>>(parent: T, acls: Vec<Acl>) -> CompositionBatch {
    let mut flow_cache: HashMap<Flow,Hashinfo> = HashMap::new();
    let mut flow: Flow = Flow {
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
        proto: 0,
    };
    
    parent
        .parse::<MacHeader>()
        .transform(box move |p| {
            p.get_mut_header().swap_addresses();
        })
        .parse::<IpHeader>()
        .filter(box move |p| {
            flow = p.get_header().flow().unwrap();
           // println!("length: {:#?}", p.get_header().length());`
           // println!("ecn: {:#?}", p.get_header().ecn());
           // println!("dscp: {:#?}", p.get_header().dscp());
           // println!("protocol: {:#?}", p.get_header().protocol());
           // println!("flags: {:#?}", p.get_header().flags());
            for acl in &acls {
                if acl.matches(&flow, &flow_cache) {
                    if !acl.drop {
                        if flow_cache.contains_key(&flow) {
                            println!("************************Hash contains flow*********************");
                            flow_cache.get_mut(&flow).unwrap().increment_details(p.get_header().length());
                        } else {
                            let mut hashinfo = Hashinfo {
                                count: 1,
                                epoch: SystemTime::now(),
                                totallength: p.get_header().length() as u32,
                                meanlength: (p.get_header().length() / 1) as u32,
                                tos: (p.get_header().dscp() << 2) | p.get_header().ecn(),
                                ttl: p.get_header().ttl(),
                                ipflags: p.get_header().flags(),
                                tcpflags: None,
                            };
                            flow_cache.insert(flow,hashinfo);
                        }
                        //    Some(h) => h.increment_count(),
                        //    None => {
                        //        let mut hashinfo = Hashinfo {
                        //            count: 1,
                        //            epoch: SystemTime::now(),
                        //        };
                        //    }
                        
                    }
                    return !acl.drop;
                }
            }
            return false;
        })
        .parse::<TcpHeader>()
        //.map(box move |p| {
        //    flow_cache.get_mut(&flow).unwrap().set_tcpflags(p.get_header().flags());
        //})
        .compose()
}
