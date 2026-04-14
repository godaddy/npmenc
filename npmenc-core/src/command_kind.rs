#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    Npm,
    Npx,
}

impl CommandKind {
    pub fn executable_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Npx => "npx",
        }
    }

    pub fn display_name(self) -> &'static str {
        self.executable_name()
    }
}
