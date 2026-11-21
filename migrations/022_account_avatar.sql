ALTER TABLE bank_account ADD COLUMN avatar TEXT CHECK (length(avatar) <= 61462);
