//! Helper module containing higher level APIs to query
//! BTF objects.

use super::*;
use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// Helper structure used to describe a BTF structure
#[derive(Debug)]
pub struct StructHelper {
    /// structure's name
    pub name: String,
    /// structure's BTF type
    pub btf_type: BtfType,
    /// members of the structure
    pub members: Vec<MemberHelper>,
}

impl Default for StructHelper {
    fn default() -> Self {
        StructHelper {
            name: "".into(),
            btf_type: BtfType::Unknown,
            members: vec![],
        }
    }
}

impl StructHelper {
    pub(crate) fn with_type(name: String, bt: BtfType) -> Self {
        StructHelper {
            name,
            btf_type: bt,
            ..Default::default()
        }
    }

    // resolve structure members recursively
    fn resolve_members_rec(
        &mut self,
        btf: &Btf,
        t: &BtfType,
        member_path: &MemberPath,
        base_offset: u32,
    ) -> Result<(), BtfError> {
        if let Some(members) = t.members() {
            let mut member_offset = base_offset;
            for m in members {
                let member_name = btf.string_at(m.name_offset)?;
                // we get the member type
                let member_type = btf.type_by_id(m.btf_type)?;
                let mut member_size = member_type.size().unwrap_or_default();

                let mut p = member_path.clone();
                // if not anonymous
                if !member_name.is_empty() {
                    p = MemberPath::from_other_with_name(member_path, member_name.to_string());
                }

                match member_type {
                    BtfType::Struct(_) => {
                        // we push the structure name
                        self.members.push(MemberHelper::new(
                            p.clone(),
                            member_offset,
                            member_type.clone(),
                            None,
                        ));
                        // we process all members of the structure
                        self.resolve_members_rec(btf, member_type, &p, member_offset)?;
                    }

                    BtfType::Union(_) => {
                        // unions don't have names so path is unchanged
                        self.resolve_members_rec(btf, member_type, member_path, member_offset)?;
                    }

                    BtfType::Array(array) => {
                        self.members.push(MemberHelper::new(
                            p,
                            member_offset,
                            member_type.clone(),
                            Some(btf.type_by_id(array.array.element_type)?.clone()),
                        ));
                    }

                    BtfType::Typedef(td) => {
                        member_size = btf.type_by_id(td.btf_type)?.size().unwrap_or_default();
                        self.members.push(MemberHelper::new(
                            p,
                            member_offset,
                            member_type.clone(),
                            None,
                        ));
                    }

                    _ => {
                        self.members.push(MemberHelper::new(
                            p,
                            member_offset,
                            member_type.clone(),
                            None,
                        ));
                    }
                }

                // members of unions all have the same offset
                if !matches!(t.kind(), BtfKind::Union) {
                    member_offset += member_size;
                }
            }
        }
        Ok(())
    }

    /// Creates a new structure descriptor for structure named `struct_name` from a [`Btf`]
    /// # Arguments
    /// * `struct_name` - must be a valid name of a structure defined inside the [`Btf`] object.
    pub fn from_btf<T: AsRef<str>>(btf: &Btf, struct_name: T) -> Result<Self, BtfError> {
        let struct_name = struct_name.as_ref();
        let i_struct = btf.id_by_type_name_kind(struct_name, BtfKind::Struct)?;
        let st = btf.type_by_id(i_struct)?;

        let mut struct_desc: Self = Self::with_type(struct_name.into(), st.clone());
        //let mp = MemberPath::with_struct_name(struct_name.into());
        let mp = MemberPath::new();

        struct_desc.resolve_members_rec(btf, st, &mp, 0)?;
        Ok(struct_desc)
    }

    /// Get the member located at path relative to the top level structure
    /// # Arguments
    /// * `p` - must be a string containing dots (.) as path separators
    pub fn get_member<P: AsRef<str>>(&self, path: P) -> Option<&MemberHelper> {
        let path = path.as_ref();
        self.members.iter().find(|m| m.is_path(path))
    }

    /// Returns the size of the [`StructHelper`]. This might not be the real size of
    /// the structure as it does not take alignement into account. In order to have
    /// the size of aligned structure use [`size_of_aligned`] method.
    ///
    /// [`size_of_aligned`]: #size_of_aligned
    pub fn size_of(&self) -> usize {
        // a simple way to get the size of the structure is to
        // get the last member offset and add the member's size to it
        if let Some(last) = self.members.last() {
            return last.offset as usize + last.size_of();
        }
        // if there is no member the structure size must be 0
        0
    }

    /// Return aligned size of structure according to architecture pointer size
    pub fn size_of_aligned(&self) -> usize {
        let un_size = self.size_of();
        let align = core::mem::size_of::<*const usize>();
        let modulo = un_size % align;
        if un_size == 0 {
            return 0;
        }

        if modulo == 0 {
            // we are already aligned
            return un_size;
        }

        // compute aligned size_of
        (un_size - modulo) + align
    }
}

/// Path of a member inside a structure
#[derive(Clone)]
pub struct MemberPath(Vec<String>);

impl MemberPath {
    pub(crate) fn new() -> Self {
        MemberPath(vec![])
    }

    pub(crate) fn from_other_with_name(o: &Self, name: String) -> Self {
        let mut new = o.clone();
        new.push_name(name);
        new
    }

    pub(crate) fn push_name(&mut self, name: String) {
        self.0.push(name)
    }

    pub(crate) fn eq_str<T: AsRef<str>>(&self, s: T) -> bool {
        s.as_ref() == self.to_string().as_str()
    }
}

impl core::fmt::Display for MemberPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.join("."))
    }
}

impl core::fmt::Debug for MemberPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.join("."))
    }
}

/// Structure holding information about BTF structure offset
#[derive(Debug)]
pub struct MemberHelper {
    /// full path of the structure member, starting with top level structure name (ex: task_struct.thread_info)
    pub path: MemberPath,
    /// relative offset (to the top level structure) of that member
    pub offset: u32,
    /// [BtfType] associated to the member
    pub btf_type: BtfType,
    /// if btf_type is a [BtfType::Array] this is the [BtfType] of the element
    pub element_type: Option<BtfType>,
}

impl MemberHelper {
    pub(crate) fn new(
        path: MemberPath,
        offset: u32,
        btf_type: BtfType,
        element_type: Option<BtfType>,
    ) -> Self {
        MemberHelper {
            path,
            offset,
            btf_type,
            element_type,
        }
    }

    /// Checks if member path matches string
    /// # Arguments
    /// * `p` - must be a string containing dots (.) as path separators
    pub fn is_path<T: AsRef<str>>(&self, p: T) -> bool {
        self.path.eq_str(p)
    }

    /// Returns member's name
    pub fn member_name(&self) -> Cow<str> {
        Cow::from(self.path.0.last().unwrap())
    }

    /// Returns the size of the BTF member
    pub fn size_of(&self) -> usize {
        // different size computation for arrays
        if let BtfType::Array(a) = &self.btf_type {
            let etype = self
                .element_type
                .as_ref()
                .expect("element type should not be missing");
            // we multiply the size of the element with the length of the array
            return (etype.size().unwrap_or_default() * a.array.len) as usize;
        }

        self.btf_type.size().unwrap_or_default() as usize
    }

    /// Returns the size of aligned member
    pub fn size_of_aligned(&self) -> usize {
        let un_size = self.size_of();
        let align = core::mem::size_of::<*const usize>();
        let modulo = un_size % align;
        if un_size == 0 {
            return 0;
        }

        if modulo == 0 {
            // we are already aligned
            return un_size;
        }

        // compute aligned size_of
        (un_size - modulo) + align
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_offsets() {
        let btf = Btf::from_sys_fs().unwrap();
        let ptr_size = core::mem::size_of::<*const u32>() as u32;

        let hlist_head = StructHelper::from_btf(&btf, "hlist_head").unwrap();
        // hlist_h ead is only one pointer
        assert_eq!(hlist_head.get_member("first").unwrap().offset, 0);

        // hlist_node is a structure of two pointers
        let hlist_node = StructHelper::from_btf(&btf, "hlist_node").unwrap();
        assert_eq!(hlist_node.get_member("next").unwrap().offset, 0);
        assert_eq!(hlist_node.get_member("pprev").unwrap().offset, ptr_size);

        let dentry = StructHelper::from_btf(&btf, "dentry").unwrap();
        assert_eq!(dentry.get_member("d_name").unwrap().offset, 32);
    }

    #[test]
    fn test_get_member() {
        let btf = Btf::from_sys_fs().unwrap();

        let mount = StructHelper::from_btf(&btf, "mount").unwrap();

        assert!(mount.get_member("mnt").is_some());
        assert!(mount.get_member("mnt.mnt_root").is_some());
        assert!(mount.get_member("mnt.mnt_sb").is_some());
        assert!(mount.get_member("mnt_parent").is_some());

        // testing unexisting members
        assert!(mount.get_member("").is_none());
        assert!(mount.get_member("mnt.unkwnown_member").is_none());
        assert!(mount.get_member("mnt.mnt_root.unk").is_none());

        let task_struct = StructHelper::from_btf(&btf, "task_struct").unwrap();
        for m in &task_struct.members {
            assert!(task_struct.get_member(m.path.to_string()).is_some());
        }
    }

    #[test]
    fn test_validate_size_of() {
        // the structures used in this test are relatively small and
        // are supposed not to change a lot accross kernels

        let btf = Btf::from_sys_fs().unwrap();
        let ptr_size = core::mem::size_of::<*const u32>();

        // hlist_h ead is only one pointer
        assert_eq!(
            StructHelper::from_btf(&btf, "hlist_head")
                .unwrap()
                .size_of_aligned(),
            ptr_size
        );

        // hlist_node is two pointers
        assert_eq!(
            StructHelper::from_btf(&btf, "hlist_node")
                .unwrap()
                .size_of_aligned(),
            ptr_size * 2
        );

        // this is a struct with a int and an array of 4 int
        let trs = StructHelper::from_btf(&btf, "task_rss_stat").unwrap();
        // unaligned size is 20
        assert_eq!(trs.size_of(), 20);
        // aligned size is 24
        if ptr_size == 8 {
            assert_eq!(trs.size_of_aligned(), 24);
        } else if ptr_size == 4 {
            assert_eq!(trs.size_of_aligned(), 20);
        }
    }
}
